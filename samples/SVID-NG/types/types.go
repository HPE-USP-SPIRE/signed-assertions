package types


type FileContents struct {
	OauthToken					string					`json:OauthToken",omitempty"`
	Msg							[]byte					`json:Msg",omitempty"`
	DASVIDToken					string					`json:DASVIDToken",omitempty"`
	ZKP							string					`json:ZKP",omitempty"`
	PubKey						[]byte					`json:PubKey",omitempty"` 
}

type PocData struct {
	AccessToken     			string					`json:",omitempty"`
	PublicKey					string					`json:",omitempty"`
	OauthSigValidation 			*bool					`json:",omitempty"`
	OauthExpValidation 			*bool					`json:",omitempty"`
	OauthExpRemainingTime		string					`json:",omitempty"`
	OauthClaims					map[string]interface{}	`json:",omitempty"`
	DASVIDToken					string					`json:",omitempty"`
	DASVIDClaims 				map[string]interface{}	`json:",omitempty"`
	DasvidExpValidation 		*bool					`json:",omitempty"`
	DasvidExpRemainingTime		string					`json:",omitempty"`
	DasvidSigValidation 		*bool					`json:",omitempty"`

	AppURI						string					`json:",omitempty"`
	Profile         			map[string]string		`json:",omitempty"`
	IsAuthenticated 			bool					`json:",omitempty"`
	HaveDASVID					bool					`json:",omitempty"`
	Returnmsg					string					`json:",omitempty"`
	Balance						int						`json:",omitempty"`
}

// Exchange code for Oauth
type Exchange struct {
	Error            			string					`json:"error,omitempty"`
	ErrorDescription 			string					`json:"error_description,omitempty"`
	AccessToken      			string					`json:"access_token,omitempty"`
	TokenType        			string					`json:"token_type,omitempty"`
	ExpiresIn        			int						`json:"expires_in,omitempty"`
	Scope            			string					`json:"scope,omitempty"`
	IdToken          			string					`json:"id_token,omitempty"`
}

type Balancetemp struct {
	User						string					`json:",omitempty"`
	Balance						int						`json:",omitempty"`
	Returnmsg					string					`json:",omitempty"`
}