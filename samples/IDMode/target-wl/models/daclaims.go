package models

type DAClaims struct {
	Iss				string `json:",omitempty"`
	Aud				string `json:",omitempty"`
	Iat			 	string `json:",omitempty"`
	Dpa				string `json:",omitempty"`
	Dpr				string `json:",omitempty"`
}

