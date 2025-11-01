package pku_disk

type ListResponse struct {
	NextMarker string     `json:"next_marker"`
	Dirs       []DirItem  `json:"dirs"`
	Files      []File 	  `json:"files"`
	DocLib     DocLib     `json:"doc_lib"`
}

type DirItem struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	ModifiedAt string    `json:"modified_at"`
	CreatedAt  string    `json:"created_at"`
	Rev        string    `json:"rev"`
}

type File struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Size               int64          `json:"size"`
	CreatedAt          string         `json:"created_at"`
	ModifiedAt         string         `json:"modified_at"`
	Rev                string         `json:"rev"`
	SecurityClassification int         `json:"security_classification"`
	StorageName        string         `json:"storage_name"`
	CustomMetadata     CustomMetadata `json:"custom_metadata"`
}

type CustomMetadata struct {
	ClientMtime int64 `json:"client_mtime"`
}

type DocLib struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ID   string `json:"id"`
}

type DownloadResponse struct {
	AuthRequest   []string `json:"authrequest"`
	ClientMtime   int64    `json:"client_mtime"`
	Size          int64    `json:"size"`
	Rev           string   `json:"rev"`
	Name          string   `json:"name"`
	NeedWatermark bool     `json:"need_watermark"`
}