package models

type FileContents struct {
	OauthClaims map[string]interface{}	`json:",omitempty"`
	DASVIDToken string					`json:",omitempty"`
	ZKP         string					`json:",omitempty"`
	Returnmsg	string					`json:",omitempty"`
	Msg			[]byte					`json:Msg",omitempty"`
}
