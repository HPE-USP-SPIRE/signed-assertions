package models

type PocData struct {
	AppURI              string
	Profile             map[string]string
	IsAuthenticated     bool
	HaveDASVID          bool
	AccessToken         string
	PublicKey           string
	SigValidation       string
	ExpValidation       string
	RetClaims           map[string]interface{}
	DASVIDToken         string
	DASVIDClaims        map[string]interface{}
	DasvidExpValidation string
	Returnmsg           string
	Balance             int
	IDArtifacts			string `json:",omitempty"`
}
