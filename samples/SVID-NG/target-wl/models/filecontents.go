package models

type FileContents struct {
	OauthClaims map[string]interface{} `json:",omitempty"`
	DASVIDToken string                 `json:",omitempty"`
	ZKP         string                 `json:",omitempty"`
}
