package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// Workload API socket path
	hostIP		= ""
	appPort		= 8443
	socketPath= "unix:///tmp/spire-agent/public/api.sock"
	serverURL	= hostIP+":"+strconv.Itoa(appPort)
)

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func main() {

// Usage: ./client <ip:port> <operation> <parameter>

// Need to create an SPIFFE Entry ID with a selector associated
// Selector example: unix:user:<your user id>
// 
// Supported Operations: mint, keys, validate
// Parameters: mint requires Oauth Token. Validate requires DASVID to be validated.

// example:
// ./client 192.168.0.5:8443 keys
// ./client mint <OAUTH TOKEN>

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var endpoint string
	if len(os.Args) < 3 {
		fmt.Println("Invalid number of arguments. Need 3, received ", len(os.Args))
		fmt.Println("Usage: ./client <ip:port> <operation> <parameter>")
		os.Exit(1)
	}
	serverURL	:= os.Args[1]
	operation	:= os.Args[2]
	var token string
	if len(os.Args) == 4 {
		token		= os.Args[3]
	}


	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	switch operation {
		case "mint":
			// mint endpoint test
			endpoint = "https://"+serverURL+"/mint?AccessToken="+token
		case "keys":
			// keys endpoint test
			endpoint = "https://"+serverURL+"/keys"
		case "validate":
			// validate endpoint test
			endpoint = "https://"+serverURL+"/validate?DASVID="+token
		case "introspect":
			// introspect endpoint test
			endpoint = "https://"+serverURL+"/introspect?DASVID="+token
	}

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", serverURL, err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	fmt.Printf("%s", body)
}