package data

var DefaultOptions = []byte(`{
	"socket_path": "unix:///tmp/agent.sock",
	"asserting_wl_ip": ":8443",
	"middle_tier_ip": ":8449",
	"proof_length": 80,
	"pem_path": "./keys/oauth.pem",
	"mint_zkp": "true",
	"trust_domain": "example.org",
	"port": ":8449"
}`)
