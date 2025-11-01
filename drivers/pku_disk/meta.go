package pku_disk

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	driver.RootID

	Username string `json:"username" required:"true" help:"北京大学统一身份账号"`
	Password string `json:"password" required:"true" help:"密码"`

	OAuthToken   string `json:"oauth_token" optional:"true" help:"自动填充：访问令牌"`
	RefreshToken string `json:"refresh_token" optional:"true" help:"自动填充：刷新令牌"`
	IDToken string `json:"id_token" optional:"true" help:"自动填充"`
}

var config = driver.Config{
	Name:              "PKU AnyShare",
	LocalSort:         false,
	OnlyProxy:         false,
	NoCache:           false,
	NoUpload:          false,
	CheckStatus:       true,
	DefaultRoot:       "0",
	Alert:             "",
	NoOverwriteUpload: false,
	NoLinkURL:         false,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &PKUDisk{}
	})
}