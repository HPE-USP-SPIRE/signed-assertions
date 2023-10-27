package data

var DefaultOptions = []byte(`{
	"socket_path": "unix:///tmp/agent.sock",
	"target_wl_ip": ":8444",
	"proof_length": 80,
	"pem_path": "./keys/oauth.pem",
	"trust_domain": "example.org",
	"port": ":8444"
}`)
