package models

type Contents struct {
	OauthSigValidation    *bool  `json:",omitempty"`
	OauthExpValidation    *bool  `json:",omitempty"`
	OauthExpRemainingTime string `json:",omitempty"`
	DASVIDToken           string `json:",omitempty"`
	IDArtifacts					string `json:",omitempty"`
}
