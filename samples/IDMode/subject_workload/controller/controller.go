package controller

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/handlers"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/local"
)

func SubjectWLController() {

	local.InitGlobals()
	local.InitTemplate()

	// Retrieve local IP
	uri := GetOutboundIP(":8080")

	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/callback", handlers.AuthCodeCallbackHandler)
	http.HandleFunc("/profile", handlers.ProfileHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)

	http.HandleFunc("/account", handlers.AccountHandler)

	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	http.HandleFunc("/get_balance", handlers.BalanceHandler)
	http.HandleFunc("/deposit", handlers.DepositHandler)
	log.Print("Subject workload starting at ", uri)
	err := http.ListenAndServe(uri, nil)
	if err != nil {
		log.Printf("the Subject workload HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}


func GetOutboundIP(port string) string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
	return uri
}
