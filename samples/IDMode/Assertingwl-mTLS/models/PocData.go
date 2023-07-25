package models

type PocData struct {
	AccessToken            string                 `json:",omitempty"`
	PublicKey              string                 `json:",omitempty"`
	OauthSigValidation     *bool                  `json:",omitempty"`
	OauthExpValidation     *bool                  `json:",omitempty"`
	OauthExpRemainingTime  string                 `json:",omitempty"`
	OauthClaims            map[string]interface{} `json:",omitempty"`
	DASVIDToken            string                 `json:",omitempty"`
	DASVIDClaims           map[string]interface{} `json:",omitempty"`
	DasvidExpValidation    *bool                  `json:",omitempty"`
	DasvidExpRemainingTime string                 `json:",omitempty"`
	DasvidSigValidation    *bool                  `json:",omitempty"`
	IDArtifacts			   string				  `json:",omitempty"`
}
