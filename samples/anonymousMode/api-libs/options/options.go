package options

type Options struct {
	SocketPath    string `json:"SOCKET_PATH" yaml:"SOCKET_PATH" mapstructure:"SOCKET_PATH" default:"unix:///tmp/agent.sock"`
	AssertingWLIP string `json:"ASSERTINGWLIP" yaml:"ASSERTINGWLIP" mapstructure:"ASSERTINGWLIP" default:":8443"`
	MiddleTierIP  string `json:"MIDDLETIERIP" yaml:"MIDDLETIERIP" mapstructure:"MIDDLETIERIP" default:":8445"`
    //MiddleTierIP  string `json:"MIDDLETIERIP" yaml:"MIDDLETIERIP" mapstructure:"MIDDLETIERIP" default:":8444"`
	ProoLength    int    `json:"PROOF_LEN" yaml:"PROOF_LEN" mapstructure:"PROOF_LEN" default:"80"`
	PemPath       string `json:"PEM_PATH" yaml:"PEM_PATH" mapstructure:"PEM_PATH" default:"./keys/oauth.pem"`
	MintZKP       string `json:"MINT_ZKP" yaml:"MINT_ZKP" mapstructure:"MINT_ZKP" default:"true"`
	AddZKP        string `json:"ADD_ZKP" yaml:"ADD_ZKP" mapstructure:"ADD_ZKP" default:"true"`
	TrustDomain   string `json:"TRUST_DOMAIN" yaml:"TRUST_DOMAIN" mapstructure:"TRUST_DOMAIN" default:"example.org"`
	Port          string `json:"port" yaml:"port" mapstructure:"port" default:":8443"`
	ClientID      string `json:"CLIENT_ID" yaml:"CLIENT_ID" mapstructure:"CLIENT_ID" default:""`
	ClientSecret  string `json:"CLIENT_SECRET" yaml:"CLIENT_SECRET" mapstructure:"CLIENT_SECRET" default:""`
	Issuer        string `json:"ISSUER" yaml:"ISSUER" mapstructure:"ISSUER" default:""`
	HostIP        string `json:"HOSTIP" yaml:"HOSTIP" mapstructure:"HOSTIP" default:""`
	TargetWLIP    string `json:"TARGETWLIP" yaml:"TARGETWLIP" mapstructure:"TARGETWLIP" default:"8444"`
}

// NewOptions returns a ptr to a new options object
func NewOptions() *Options {
	return &Options{}
}

// InitOptions initializes the options
func InitOptions() (*Options, error) {
	// init service options
	options := NewOptions()
	// if err := json.Unmarshal(data.DefaultOptions, options); err != nil {
	// 	return nil, fmt.Errorf("Options initialization unmarshal error: %v", err)
	// }
	return options, nil
}
