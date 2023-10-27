package controller

import (
	"context"
	"log"
	"net/http"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/Assertingwl-mTLS/router"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/Assertingwl-mTLS/local"
)

type maxBytesHandler struct {
	h http.Handler
	n int64
}

// ServeHTTP uses MaxByteReader to limit the size of the input
func (h *maxBytesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.n)
	h.h.ServeHTTP(w, r)
}

func WLController(ctx context.Context) {

	local.InitGlobals()

	r, err := router.AssertingWLRouter(ctx)
	if err != nil {
		log.Fatalf("Error creating router: %v", err)
	}

	maxHandler := &maxBytesHandler{h: r, n: 1048576}

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	log.Printf("local.Options=%+v", local.Options)
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(local.Options.SocketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - Client must be from this trust domain
	clientID := spiffeid.RequireTrustDomainFromString(local.Options.TrustDomain)

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
	server := &http.Server{
		Addr:      local.Options.Port,
		TLSConfig: tlsConfig,
		Handler:   maxHandler,
	}

	log.Printf("Start serving asserting-wl API at %s", local.Options.Port)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Error on serve: %v", err)
	}
}
