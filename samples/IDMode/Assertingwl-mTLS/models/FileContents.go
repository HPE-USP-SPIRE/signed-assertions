package models

type FileContents struct {
	OauthToken  string `json:OauthToken",omitempty"`
	Msg         []byte `json:Msg",omitempty"`
	DASVIDToken string `json:DASVIDToken",omitempty"`
	ZKP         string `json:ZKP",omitempty"`
	PubKey      []byte `json:PubKey",omitempty"`
}
