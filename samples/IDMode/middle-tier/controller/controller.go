package controller

import (
	"context"
	"log"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier/local"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier/router"
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

func MiddleTierController(ctx context.Context) {
	local.InitGlobals()
	log.Printf("final init options: %+v", local.Options)

	r, err := router.MiddleTierRouter(ctx)
	if err != nil {
		log.Fatalf("Error creating router: %v", err)
	}

	maxHandler := &maxBytesHandler{h: r, n: 1048576}

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(local.Options.SocketPath)),
	)
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

	log.Printf("Start serving Middle tier API at post %s", local.Options.Port)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Error on serve: %v", err)
	}
}
