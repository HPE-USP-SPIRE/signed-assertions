package router

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	muxprom "gitlab.com/msvechla/mux-prometheus/pkg/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/Assertingwl-mTLS/handlers"
)

func AssertingWLRouter(ctx context.Context) (*mux.Router, error) {

	s := mux.NewRouter()

	instrumentation := muxprom.NewDefaultInstrumentation()
	s.Use(instrumentation.Middleware)
	s.Path("/metrics").Handler(promhttp.Handler())

	s.HandleFunc("/mint", handlers.MintHandler).Methods("GET")
	s.HandleFunc("/keys", handlers.KeysHandler).Methods("GET")
	s.HandleFunc("/validate", handlers.ValidateDasvidHandler).Methods("GET")
	s.HandleFunc("/introspect", handlers.IntrospectHandler).Methods("GET")
	s.HandleFunc("/ecdsaassertion", handlers.ECDSAAssertionHandler).Methods("GET")

	s.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return s, nil
}
