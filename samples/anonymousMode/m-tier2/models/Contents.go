package models

type Contents struct {
	DasvidExpValidation    *bool  `json:",omitempty`
	DasvidExpRemainingTime string `json:",omitempty`
	DasvidSigValidation    *bool  `json:",omitempty`
	DASVIDToken            string `json:",omitempty`
}
