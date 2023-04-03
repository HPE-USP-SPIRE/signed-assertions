package main

import (
	"log"
	"net/http"
	"os"

	// To sig. validation 
	_ "crypto/sha256"
	
	"subjectwl/api"
	"SVID-NG/utils"
)


func main() {

	utils.ParseEnvironment()

	// Retrieve local IP
	uri := utils.GetOutboundIP(":8080")

	http.HandleFunc("/", api.HomeHandler)
	http.HandleFunc("/login", api.LoginHandler)
	http.HandleFunc("/callback", api.AuthCodeCallbackHandler)
	http.HandleFunc("/profile", api.ProfileHandler)
	http.HandleFunc("/logout", api.LogoutHandler)

	http.HandleFunc("/account", api.AccountHandler)
	http.HandleFunc("/get_balance", api.Get_balanceHandler)
	http.HandleFunc("/deposit", api.DepositHandler)

	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	log.Print("Subject workload starting at ", uri)
	err := http.ListenAndServe(uri, nil)
	if err != nil {
		log.Printf("the Subject workload HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}