package constants

// Constants for the API

// global constants
const (
	ENV_SOCKET_PATH     string = "SOCKET_PATH"
	ENV_ASSERTING_WL_IP string = "ASSERTINGWLIP"
	ENV_MIDDLE_TIER_IP 	string = "MIDDLETIERIP"
	ENV_MIDDLE_TIER2_IP string = "MIDDLE_TIER2_IP"
	ENV_MIDDLE_TIER3_IP string = "MIDDLE_TIER3_IP"
	ENV_MIDDLE_TIER4_IP string = "MIDDLE_TIER4_IP"
	ENV_MIDDLE_TIER5_IP string = "MIDDLE_TIER5_IP"
	ENV_PROOF_LENGTH    string = "PROOF_LEN"
	ENV_PEM_PATH        string = "PEM_PATH"
	ENV_MINT_ZKP        string = "MINT_ZKP"
	ENV_ADD_ZKP         string = "ADD_ZKP"
	ENV_TRUST_DOMAIN    string = "TRUST_DOMAIN"
	ENV_CLIENT_ID       string = "CLIENT_ID"
	ENV_CLIENT_SECRET   string = "CLIENT_SECRET"
	ENV_ISSUER          string = "ISSUER"
	ENV_HOST_IP         string = "HOSTIP"
	ENV_TARGET_WL_IP    string = "TARGETWLIP"
)

// global int constants related to
// port numbers used by middle tiers.
const (
    MIDDLE_TIER_PORT     int = 8445 
    MIDDLE_TIER2_PORT    int = 8446 
    MIDDLE_TIER3_PORT    int = 8447 
    MIDDLE_TIER4_PORT    int = 8448 
    MIDDLE_TIER5_PORT    int = 8449 
)
