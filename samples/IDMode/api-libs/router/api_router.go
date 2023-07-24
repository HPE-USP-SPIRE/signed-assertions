package router

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/api-libs/handlers"
)

func LSVIDApiRouter() (*mux.Router, error) {

	mwr := mux.NewRouter()

	s := mwr.PathPrefix("/api/v1").Methods("GET", "POST", "PUT", "DELETE").Subrouter()

	s.HandleFunc("/get_balance", handlers.BalanceHandler).Methods("GET")
	s.HandleFunc("/deposit", handlers.DepositHandler).Methods("POST")

	mwr.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return mwr, nil
}
