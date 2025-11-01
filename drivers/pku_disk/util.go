package pku_disk

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/go-resty/resty/v2"
)


const (
	BaseURL   = "https://disk.pku.edu.cn"
	IaaaLogin = "https://iaaa.pku.edu.cn/iaaa/oauthlogin.do"
	SigninURL = "https://disk.pku.edu.cn/oauth2/signin"
	ApiPrefix = "/api/efast/v1"
)

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func extractChallenge(rawURL string) (string, error) {
	re := regexp.MustCompile(`login_challenge=([^&]+)`)
	match := re.FindStringSubmatch(rawURL)
	if len(match) < 2 {
		return "", fmt.Errorf("cannot extract login_challenge")
	}
	return match[1], nil
}

func newClient(oauthToken, refreshToken, idToken string) *resty.Client {
	client := resty.New().
		SetBaseURL(BaseURL).
		SetTimeout(30 * time.Second).
		SetHeader("User-Agent", "OpenList-PKU-Driver/1.1")
	
	jar, _ := cookiejar.New(nil)
	client.SetCookieJar(jar)

	var cookies []*http.Cookie

	if oauthToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name:   "client.oauth2_token",
			Value:  oauthToken,
			Domain: "disk.pku.edu.cn",
			Path:   "/",
		})
	}
	if refreshToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name:   "client.oauth2_refresh_token",
			Value:  refreshToken,
			Domain: "disk.pku.edu.cn",
			Path:   "/",
		})
	}
	if idToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name:   "id_token",
			Value:  idToken,
			Domain: "disk.pku.edu.cn",
			Path:   "/",
		})
	}

	u, _ := url.Parse(BaseURL)
	for _, c := range cookies {
		jar.SetCookies(u, []*http.Cookie{c})
	}
	
	return client
}

func (d *PKUDisk) setBearer(token string) {
	d.client.SetHeader("Authorization", "Bearer "+token)
}

func (d *PKUDisk) verifyToken() (bool, error) {
	var result map[string]interface{}
	resp, err := d.client.R().
		SetResult(&result).
		Post("/api/eacp/v1/user/get")
	if err != nil {
		return false, err
	}
	return resp.StatusCode() == http.StatusOK, nil
}

func (d *PKUDisk) listDocumentLibs(ctx context.Context) ([]model.Obj, error) {
	var libs []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		Rev        string `json:"rev"`
		CreatedAt  string `json:"created_at"`
		ModifiedAt string `json:"modified_at"`
	}

	resp, err := d.client.R().
		SetContext(ctx).
		SetResult(&libs).
		Get("/api/efast/v1/entry-doc-lib")

	if err != nil {
		return nil, fmt.Errorf("failed to fetch entry-doc-lib: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("entry-doc-lib api error: %s", resp.String())
	}

	var objs []model.Obj
	for _, lib := range libs {
		objs = append(objs, &model.Object{
			ID:       lib.ID,
			Name:     lib.Name,
			IsFolder:    true,
			Modified: parseTime(lib.ModifiedAt),
			Ctime: parseTime(lib.CreatedAt),
		})
	}

	return objs, nil
}

func (d *PKUDisk) SliceMD5(r io.ReadSeeker, n int64) ([]byte, string, error) {
	buf := make([]byte, n)
	read, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return nil, "", err
	}
	r.Seek(0, io.SeekStart)

	md5hash := md5.Sum(buf[:read])
	return buf[:read], hex.EncodeToString(md5hash[:]), nil
}

type PredUploadResponse struct {
	Match  bool   `json:"match"`
}

func (d *PKUDisk) predUpload(ctx context.Context, sliceMD5 string, length int64) (bool, error) {
	var resp PredUploadResponse
	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"slice_md5": sliceMD5,
			"length":    length,
		}).
		SetResult(&resp).
		Post("/api/efast/v1/file/predupload")

	if err != nil {
		return false, err
	}

	return resp.Match, nil
}

func (d *PKUDisk) dupload(ctx context.Context, parentID, name string, file model.FileStreamer) (*model.Object, error) {
	// 全量计算 md5 和 crc32 暂时没用
	type DUploadRequest struct {
		ClientMtime int64  `json:"client_mtime"`
		CRC32       string `json:"crc32"`
		MD5         string `json:"md5"`
		DocID       string `json:"docid"`
		Name        string `json:"name"`
		OnDup       int    `json:"ondup"`
		Length      int64  `json:"length"`
		CSFLevel    int    `json:"csflevel"`
	}

	type DUploadResponse struct {
		DocID    string `json:"docid"`
		Name     string `json:"name"`
		Rev      string `json:"rev"`
		Editor   string `json:"editor"`
		Modified int64  `json:"modified"` // us
		Success  bool   `json:"success"`
	}
	h1 := md5.New()
	h2 := crc32.NewIEEE()
	multiWriter := io.MultiWriter(h1, h2)
	io.Copy(multiWriter, file)
	md5Sum, crc32Hex := hex.EncodeToString(h1.Sum(nil)), fmt.Sprintf("%x", h2.Sum32())

	reqBody := DUploadRequest{
		ClientMtime: file.ModTime().UnixNano() / 1000,
		CRC32:       crc32Hex,
		MD5:         md5Sum,
		DocID:       parentID,
		Name:        name,
		OnDup:       1,
		Length:      file.GetSize(),
		CSFLevel:    0,
	}

	var resp DUploadResponse
	_, err := d.client.R().
		SetContext(ctx).
		SetBody(reqBody).
		SetResult(&resp).
		Post("/api/efast/v1/file/dupload")

	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("dupload failed: not successful")
	}

	return &model.Object{
		ID:       resp.DocID,
		Name:     resp.Name,
		Size:     reqBody.Length,
		IsFolder:    false,
		Modified: time.Unix(0, resp.Modified*1000),
		Ctime: time.Unix(0, resp.Modified*1000),
	}, nil
}

func (d *PKUDisk) osBeginUpload(ctx context.Context, parentID, name string, size int64, mtime int64) (authReq []string, docID, newName, rev string, err error) {
	var resp struct {
		AuthRequest []string `json:"authrequest"`
		DocID       string   `json:"docid"`
		Name        string   `json:"name"`
		Rev         string   `json:"rev"`
	}

	_, err = d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"usehttps":     true,
			"reqmethod":    "POST",
			"name":         name,
			"docid":        parentID,
			"ondup":        1,
			"length":       size,
			"client_mtime": mtime,
		}).
		SetResult(&resp).
		Post("/api/efast/v1/file/osbeginupload")

	if err != nil {
		return nil, "", "", "", fmt.Errorf("failed to call osbeginupload: %w", err)
	}
	if len(resp.AuthRequest) == 0 {
		return nil, "", "", "", fmt.Errorf("empty authrequest in response")
	}

	return resp.AuthRequest, resp.DocID, resp.Name, resp.Rev, nil
}

func parseAuthRequest(authReq []string) (method, url string, headers map[string]string, key string) {
	headers = make(map[string]string)

	for i, line := range authReq {
		line = strings.TrimSpace(line)
		if i == 0 {
			method = line
		} else if i == 1 {
			url = line
		} else if strings.Contains(line, ": ") {
			parts := strings.SplitN(line, ": ", 2)
			k := parts[0]
			v := parts[1]
			headers[k] = v
			if k == "key" {
				key = v
			}
		}
	}

	return method, url, headers, key
}

func (d *PKUDisk) uploadWithForm(
	ctx context.Context,
	uploadURL string,
	formFields map[string]string,
	key string,
	reader io.Reader,
	up driver.UpdateProgress,
) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for k, v := range formFields {
		if k == "key" {
			continue
		}
		if err := writer.WriteField(k, v); err != nil {
			return fmt.Errorf("write field %s failed: %w", k, err)
		}
	}

	if err := writer.WriteField("key", key); err != nil {
		return fmt.Errorf("write field key failed: %w", err)
	}

	filePart, err := writer.CreateFormFile("file", "upload.bin") // 文件名无关紧要
	if err != nil {
		return fmt.Errorf("create form file failed: %w", err)
	}

	var dst io.Writer = filePart
	if up != nil {
		dst = &progressWriter{w: filePart, update: up}
	}

	_, err = io.Copy(dst, reader)
	if err != nil {
		return fmt.Errorf("copy file data failed: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("close multipart writer failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", uploadURL, body)
	if err != nil {
		return fmt.Errorf("new request failed: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	httpClient := d.client.GetClient()
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

type progressWriter struct {
	w      io.Writer
	n      int64
	update driver.UpdateProgress
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.w.Write(p)
	pw.n += int64(n)
	if pw.update != nil {
		pw.update(float64(pw.n))
	}
	return n, err
}

func (d *PKUDisk) osEndUpload(ctx context.Context, docID, rev string) error {
	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":    docID,
			"rev":      rev,
			"csflevel": 0,
		}).
		Post("/api/efast/v1/file/osendupload")

	if err != nil {
		return fmt.Errorf("osendupload request failed: %w", err)
	}

	return nil
}