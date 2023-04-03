package main

import (
	
	"log"
	"net/http"
	"os"
	"context"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	
	// dasvid lib
	"assertingwl/api"
	"SVID-NG/utils"

)

func main() {

	// Parse environment for asserting workload main
	utils.ParseEnvironment()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/mint", api.MintHandler)
	http.HandleFunc("/keys", api.KeysHandler)
	http.HandleFunc("/validate", api.ValidateDasvidHandler)
	http.HandleFunc("/introspect", api.IntrospectHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Printf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - In PoC, Clients must be from the same trust domain
	clientID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))
	
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed ClientID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
	
	log.Printf("Start serving API...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Printf("Error on serve: %v", err)
	}
	
}
