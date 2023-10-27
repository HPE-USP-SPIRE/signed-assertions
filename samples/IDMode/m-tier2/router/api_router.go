package router

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier2/handlers"
)

func MiddleTierRouter(ctx context.Context) (*mux.Router, error) {
	s := mux.NewRouter()

	s.HandleFunc("/get_balance", handlers.GetBalanceHandler).Methods("POST")
	s.HandleFunc("/deposit", handlers.DepositHandler).Methods("POST")

	s.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return s, nil
}
