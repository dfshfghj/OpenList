package pku_disk

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/go-resty/resty/v2"
)

type PKUDisk struct {
	model.Storage
	Addition
	client *resty.Client
}

func (d *PKUDisk) Config() driver.Config {
	return config
}
func (d *PKUDisk) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *PKUDisk) Init(ctx context.Context) error {
	d.client = newClient(d.OAuthToken, d.RefreshToken, d.IDToken)

	if d.OAuthToken != "" {
		d.setBearer(d.OAuthToken)
		if ok, _ := d.verifyToken(); ok {
			return nil
		}
	}

	if d.RefreshToken != "" {
		if err := d.refreshToken(ctx); err == nil {
			d.setBearer(d.OAuthToken)
			op.MustSaveDriverStorage(d)
			return nil
		}
	}

	if err := d.performLogin(ctx); err != nil {
		return err
	}

	d.setBearer(d.OAuthToken)
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *PKUDisk) performLogin(ctx context.Context) error {
	fmt.Print("[DEBUG] Login\n")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://disk.pku.edu.cn/anyshare/oauth2/login?lang=zh-cn&redirect=%2Fanyshare%2Fzh-cn%2Fhomepage",
		nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	challenge, err := extractChallenge(resp.Request.URL.String())
	if err != nil {
		return err
	}

	loginCookie := &http.Cookie{Name: "login_challenge", Value: challenge}

	// Step 2: 登录 IAAA
	formData := url.Values{}
	formData.Set("appid", "anyshare")
	formData.Set("userName", d.Username)
	formData.Set("password", d.Password)
	formData.Set("randCode", "")
	formData.Set("smsCode", "")
	formData.Set("otpCode", "")
	formData.Set("redirUrl", "https://disk.pku.edu.cn/oauth2/signin")

	req2, err := http.NewRequestWithContext(ctx, "POST", IaaaLogin, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(loginCookie)

	resp2, err := httpClient.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body2, &result); err != nil {
		return fmt.Errorf("parse iaaa response failed: %w", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("iaaa login failed: %s", result["msg"].(string))
	}
	token := result["token"].(string)

	rand := fmt.Sprintf("%v", rand.Float32())
	req3, _ := http.NewRequestWithContext(ctx, "GET", SigninURL, nil)
	q := req3.URL.Query()
	q.Set("_rand", rand)
	q.Set("token", token)
	req3.URL.RawQuery = q.Encode()
	req3.AddCookie(loginCookie)

	resp3, err := httpClient.Do(req3)
	if err != nil {
		return err
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != 200 {
		return fmt.Errorf("signin failed: %d", resp3.StatusCode)
	}

	pkuURL, _ := url.Parse("https://disk.pku.edu.cn")
	cookies := jar.Cookies(pkuURL)

	for _, c := range cookies {
		if c.Name == "client.oauth2_token" {
			d.OAuthToken = c.Value
		}
		if c.Name == "client.oauth2_refresh_token" {
			d.RefreshToken = c.Value
		}
		if c.Name == "id_token" {
			d.IDToken = c.Value
		}
	}
	if d.OAuthToken == "" {
		return fmt.Errorf("failed to get oauth token from cookies")
	}

	return nil
}

func (d *PKUDisk) refreshToken(ctx context.Context) error {
	fmt.Print("INFO[PKU DISK] refresh token")
	resp, err := d.client.R().
		SetContext(ctx).
		Get("/anyshare/oauth2/login/refreshToken")
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode(), result.Message)
	}

	fmt.Printf("INFO[PKU DISK]%s \n", result.Message)

	u, _ := url.Parse("https://disk.pku.edu.cn")
	for _, c := range d.client.GetClient().Jar.Cookies(u) {
		if c.Name == "client.oauth2_token" {
			d.OAuthToken = c.Value
		}
		if c.Name == "client.oauth2_refresh_token" {
			d.RefreshToken = c.Value
		}
		if c.Name == "id_token" {
			d.IDToken = c.Value
		}
	}

	return nil
}

func (d *PKUDisk) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(dir.GetID())
	if trimmed == "" || trimmed == "0" || trimmed == "root" {
		return d.listDocumentLibs(ctx)
	}

	folderID := d.RootID.RootFolderID
	if dir != nil && dir.GetID() != "" {
		folderID = dir.GetID()
	}

	url := fmt.Sprintf("%s/folders/%s/sub_objects?limit=100&sort=name&direction=asc&permission_attributes_required=false",
		ApiPrefix, url.PathEscape(folderID))
	var resp ListResponse
	_, err := d.client.R().
		SetContext(ctx).
		SetResult(&resp).
		Get(url)

	if err != nil {
		return nil, err
	}

	var objs []model.Obj
	for _, item := range resp.Dirs {
		objs = append(objs, &model.Object{
			ID:       item.ID,
			Name:     item.Name,
			Size:     0,
			IsFolder:    true,
			Modified: parseTime(item.ModifiedAt),
			Ctime: parseTime(item.CreatedAt),
		})
	}
	for _, item := range resp.Files {
		objs = append(objs, &model.Object{
			ID:       item.ID,
			Name:     item.Name,
			Size:     item.Size,
			IsFolder:    false,
			Modified: parseTime(item.ModifiedAt),
		})
	}

	return objs, nil
}

func (d *PKUDisk) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	filename := file.GetName()

	var downloadResp DownloadResponse
	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":      file.GetID(),
			"authtype":   "QUERY_STRING",
			"savename":   filename,
			"usehttps":   true,
			"rev":        "",
		}).
		SetResult(&downloadResp).
		Post("/api/efast/v1/file/osdownload")

	if err != nil {
		return nil, fmt.Errorf("get download link failed: %w", err)
	}

	if len(downloadResp.AuthRequest) != 2 || downloadResp.AuthRequest[0] != "GET" {
		return nil, fmt.Errorf("invalid authrequest in response")
	}

	url := downloadResp.AuthRequest[1]

	return &model.Link{
		URL:      url,
	}, nil
}
func (d *PKUDisk) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) (model.Obj, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	parentID := parentDir.GetID()

	var resp struct {
		DocID       string `json:"docid"`
		Rev         string `json:"rev"`
		Modified    int64  `json:"modified"`    // ms
		CreateTime  int64  `json:"create_time"` // ms
	}

	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":   parentID,
			"name":    dirName,
			"ondup":   1,
		}).
		SetResult(&resp).
		Post("/api/efast/v1/dir/create")

	if err != nil {
		return nil, fmt.Errorf("make directory failed: %w", err)
	}

	modTime := time.Unix(0, resp.Modified*1000) // ms -> ns
	createTime := time.Unix(0, resp.CreateTime*1000)

	return &model.Object{
		ID:       resp.DocID,
		Name:     dirName,
		IsFolder:    true,
		Modified: modTime,
		Ctime: createTime,
	}, nil
}

func (d *PKUDisk) Move(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	fmt.Printf("INFO[PKU DISK] move %s to %s\n", srcObj.GetName(), dstDir.GetName())
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	srcID := srcObj.GetID()
	if srcID == "" {
		return nil, fmt.Errorf("source object has no ID")
	}

	destParentID := dstDir.GetID()
	if destParentID == "" {
		return nil, fmt.Errorf("destination directory has no ID")
	}

	var resp struct {
		DocID string `json:"docid"`
	}

	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":       srcID,
			"destparent":  destParentID,
			"ondup":       1,
		}).
		SetResult(&resp).
		Post("/api/efast/v1/file/move")

	if err != nil {
		return nil, fmt.Errorf("move failed: %w", err)
	}

	return &model.Object{
		ID:       resp.DocID,
		Name:     srcObj.GetName(),
		Size:     srcObj.GetSize(),
		IsFolder:    srcObj.IsDir(),
		Modified: time.Now(),
	}, nil
}

func (d *PKUDisk) Rename(ctx context.Context, srcObj model.Obj, newName string) (model.Obj, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	docID := srcObj.GetID()
	if docID == "" {
		return nil, fmt.Errorf("source object has no ID")
	}

	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":  docID,
			"name":   newName,
			"ondup":  1,
		}).
		Post("/api/efast/v1/file/rename")

	if err != nil {
		return nil, fmt.Errorf("rename failed: %w", err)
	}

	return &model.Object{
		ID:       docID,
		Name:     newName,
		Size:     srcObj.GetSize(),
		IsFolder:    srcObj.IsDir(),
		Modified: time.Now(),
	}, nil
}

func (d *PKUDisk) Copy(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	srcID := srcObj.GetID()
	if srcID == "" {
		return nil, fmt.Errorf("source object has no ID")
	}

	destParentID := dstDir.GetID()
	if destParentID == "" {
		return nil, fmt.Errorf("destination directory has no ID")
	}

	var resp struct {
		DocID string `json:"docid"`
	}

	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]interface{}{
			"docid":      srcID,
			"destparent": destParentID,
			"ondup":      1,
		}).
		SetResult(&resp).
		Post("/api/efast/v1/file/copy")

	if err != nil {
		return nil, fmt.Errorf("copy failed: %w", err)
	}

	return &model.Object{
		ID:       resp.DocID,
		Name:     srcObj.GetName(),
		Size:     srcObj.GetSize(),
		IsFolder:    srcObj.IsDir(),
		Modified: time.Now(),
	}, nil
}

func (d *PKUDisk) Remove(ctx context.Context, obj model.Obj) error {
	if err := d.Init(ctx); err != nil {
		return err
	}
	docID := obj.GetID()
	if docID == "" {
		return fmt.Errorf("no id for object")
	}
	fmt.Printf("INFO[PKU DISK] rm %s \n", docID)
	_, err := d.client.R().
		SetContext(ctx).
		SetBody(map[string]string{
			"docid": docID,
		}).
		Post("/api/efast/v1/file/delete")
	if err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}

	return nil
}

func (d *PKUDisk) Put(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	if err := d.Init(ctx); err != nil {
		return nil, err
	}

	parentID := dstDir.GetID()
	filename := file.GetName()
	fileSize := file.GetSize()

	sliceReader, err := file.RangeRead(http_range.Range{Start: 0, Length: 200*1024})
	if err != nil {
		return nil, fmt.Errorf("range read failed: %w", err)
	}
	sliceBytes, err := io.ReadAll(sliceReader)
	if err != nil {
		return nil, err
	}
	sliceMD5 := fmt.Sprintf("%x", md5.Sum(sliceBytes))
	fmt.Printf("slice_md5: %s \n", sliceMD5)

	match, err := d.predUpload(ctx, sliceMD5, fileSize)
	if err != nil {
		return nil, fmt.Errorf("predupload check failed: %w", err)
	}
	if match {
		// todo
		fmt.Print("INFO[PKU DISK] matched file \n")
		/* 秒传不太稳定
		return &model.Object{
			ID:       "",
			Name:     filename,
			Size:     fileSize,
			IsFolder:    false,
			Modified: time.Now(),
		}, nil
		*/
	}

	authReq, newDocID, newName, newRev, err := d.osBeginUpload(ctx, parentID, filename, fileSize, file.ModTime().UnixNano()/1000)
	if err != nil {
		return nil, err
	}

	method, uploadURL, formFields, key := parseAuthRequest(authReq)
	if method != "POST" {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	err = d.uploadWithForm(ctx, uploadURL, formFields, key, file, up)
	if err != nil {
		return nil, fmt.Errorf("upload failed: %w", err)
	}

	err = d.osEndUpload(ctx, newDocID, newRev)
	if err != nil {
		return nil, fmt.Errorf("finalize upload failed: %w", err)
	}

	return &model.Object{
		ID:       newDocID,
		Name:     newName,
		Size:     fileSize,
		IsFolder:    false,
		Modified: time.Now(),
	}, nil
}

func (d *PKUDisk) Drop(ctx context.Context) error {
	return nil
}

func (d *PKUDisk) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	// TODO return storage details (total space, free space, etc.)
	return nil, errs.NotImplement
}

var _ driver.Driver = (*PKUDisk)(nil)