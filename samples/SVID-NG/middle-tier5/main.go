package main

/*
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "./poclib/rsa_sig_proof.h"
#include "./poclib/rsa_bn_sig.h"
#include "./poclib/rsa_sig_proof_util.h"

#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}

*/
import "C"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"
)

type FileContents struct {
	OauthToken					string `json:OauthToken",omitempty"`
	Msg							[]byte `json:Msg",omitempty"`
	DASVIDToken					string `json:DASVIDToken",omitempty"`
	ZKP							string `json:ZKP",omitempty"`
	Returnmsg					string `json:",omitempty"`
}


type Contents struct {
	DasvidExpValidation 		*bool `json:",omitempty"`
	DasvidExpRemainingTime		string `json:",omitempty"`
	DasvidSigValidation 		*bool `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
}

type Balancetemp struct {
	User						string `json:",omitempty"`
	Balance						int `json`
	Returnmsg					string `json:",omitempty"`
}

var temp Contents

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)

	// If the file doesn't exist, create it, or append to the file
	file, err := os.OpenFile("./bench.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Writing to file...")
	json.NewEncoder(file).Encode(fmt.Sprintf("%s execution time is %s", name, elapsed))
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
}

func main() {

	ParseEnvironment()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/get_balance", Get_balanceHandler)
	http.HandleFunc("/deposit", DepositHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - Client must be from this trust domain
	clientID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))
	
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
	server := &http.Server{
		Addr:      ":8449",
		TLSConfig: tlsConfig,
	}
	
	log.Printf("Start serving Middle tier 2 API...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Error on serve: %v", err)
	}
	
}

func Get_balanceHandler(w http.ResponseWriter, r *http.Request) {
	
	defer timeTrack(time.Now(), "Get_balanceHandler")

	var tempbalance Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Validate DASVID
	datoken := r.FormValue("DASVID")
	endpoint := "https://"+os.Getenv("ASSERTINGWLIP")+"/validate?DASVID="+datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	var returnmsg string

	log.Println("Sig validation: ", *temp.DasvidSigValidation)
	log.Println("exp validation: ", *temp.DasvidExpValidation)

	if (*temp.DasvidSigValidation == false) {
				
		returnmsg = "DA-SVID signature validation error"

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	if (*temp.DasvidExpValidation == false) {
				
		returnmsg = "DA-SVID expiration validation error"
		log.Println("Return Msg: ", tempbalance.Returnmsg)

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	// Contact Asserting Workload /introspect and retrieve a ZKP proving OAuth token signature
	var introspectrsp FileContents
	introspectrsp = introspect(r.FormValue("DASVID"), *client)
	if introspectrsp.Returnmsg != "" {
		log.Println("ZKP error! %v", introspectrsp.Returnmsg)
		json.NewEncoder(w).Encode(introspectrsp)
	}

	// Create OpenSSL vkey using DASVID
	tmpvkey := dasvid.Token2vkey(r.FormValue("DASVID"), 1)

	// Verify /introspect response correctness.
	hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
	if hexresult == false {
		log.Fatal("Error verifying hexproof!!")
	}
	log.Println("Success verifying hexproof in middle-tier2!!")

	// Access Target WL and request DASVID user balance
	endpoint = "https://"+os.Getenv("TARGETWLIP")+"/get_balance?DASVID="+r.FormValue("DASVID")

	response, err = client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
	}

	defer response.Body.Close()
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		fmt.Println("error:", err)
	}

	json.NewEncoder(w).Encode(tempbalance)

}

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "DepositHandler")
		

		var tempbalance Balancetemp

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
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

		// Validate DASVID
		endpoint := "https://"+os.Getenv("ASSERTINGWLIP")+"/validate?DASVID="+r.FormValue("DASVID")

		response, err := client.Get(endpoint)
		if err != nil {
			log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
		}

		defer response.Body.Close()
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("Unable to read body: %v", err)
		}

		err = json.Unmarshal([]byte(body), &temp)
		if err != nil {
			log.Fatalf("error:", err)
		}

		var returnmsg string

		log.Println("Sig validation: ", *temp.DasvidSigValidation)
		log.Println("exp validation: ", *temp.DasvidExpValidation)

		if (*temp.DasvidSigValidation == false) {
					
			returnmsg = "DA-SVID signature validation error"

			tempbalance = Balancetemp{
				User:		"",
				Balance:	0,
				Returnmsg: 	returnmsg,
			}

			json.NewEncoder(w).Encode(tempbalance)
			return
		}

		if (*temp.DasvidExpValidation == false) {
					
			returnmsg = "DA-SVID expiration validation error"
			log.Println("Return Msg: ", tempbalance.Returnmsg)

			tempbalance = Balancetemp{
				User:		"",
				Balance:	0,
				Returnmsg: 	returnmsg,
			}

			json.NewEncoder(w).Encode(tempbalance)
			return
		}

		// Contact Asserting Workload /introspect and retrieve a ZKP proving OAuth token signature
		var introspectrsp FileContents
		introspectrsp = introspect(r.FormValue("DASVID"), *client)
		if introspectrsp.Returnmsg != "" {
			log.Println("ZKP error! %v", introspectrsp.Returnmsg)
			json.NewEncoder(w).Encode(introspectrsp)
		}

		// MODIFICATIONS TO BENCHMARK THE SOLUTION. REMOVE AFTER
		// benchmark zkp validation process
	for i:=0; i<1; i++ {
		log.Printf("Execution number: %v", i)
		defer timeTrack(time.Now(), fmt.Sprintf("ZKP validation : %v", i))

		// Create OpenSSL vkey using DASVID
		tmpvkey := dasvid.Token2vkey(r.FormValue("DASVID"), 1)

		// Verify /introspect response correctness.
		hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
		if hexresult == false {
			log.Fatal("Error verifying hexproof!!")
		}
		log.Println("Success verifying hexproof in middle-tier2!!")
	}
		// Gera chamada para target workload 
		endpoint = "https://"+os.Getenv("TARGETWLIP")+"/deposit?DASVID="+r.FormValue("DASVID")+"&deposit="+r.FormValue("deposit")

		response, err = client.Get(endpoint)
		if err != nil {
			log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
		}

		defer response.Body.Close()
		body, err = ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("Unable to read body: %v", err)
		}

		// Receive data and return it to subject.
		err = json.Unmarshal([]byte(body), &tempbalance)
		if err != nil {
			fmt.Println("error:", err)
		}

		json.NewEncoder(w).Encode(tempbalance)	
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

func introspect(datoken string, client http.Client) (introspectrsp FileContents) {
	
		// Introspect DA-SVID
		// var returnmsg string
		var rcvresp FileContents

		endpoint := "https://"+os.Getenv("ASSERTINGWLIP")+"/introspect?DASVID="+datoken

		response, err := client.Get(endpoint)
		if err != nil {
			log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
		}

		defer response.Body.Close()
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("Unable to read body: %v", err)
		}

		err = json.Unmarshal([]byte(body), &rcvresp)
		if err != nil {
			log.Fatalf("error:", err)
		}

		introspectrsp = FileContents{
			Msg			: rcvresp.Msg,
			ZKP		 	:	rcvresp.ZKP,
			Returnmsg	:  "",
		}
	return introspectrsp
}


func ParseEnvironment() {

	if _, err := os.Stat(".cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
	}

	setEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("ASSERTINGWLIP", os.Getenv("ASSERTINGWLIP"))
	if os.Getenv("ASSERTINGWLIP") == "" {
		log.Printf("Could not resolve a ASSERTINGWLIP environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("TARGETWLIP", os.Getenv("TARGETWLIP"))
	if os.Getenv("TARGETWLIP") == "" {
		log.Printf("Could not resolve a TARGETWLIP environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("PROOF_LEN", os.Getenv("PROOF_LEN"))
	if os.Getenv("PROOF_LEN") == "" {
		log.Printf("Could not resolve a PROOF_LEN environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("PEM_PATH", os.Getenv("PEM_PATH"))
	if os.Getenv("PEM_PATH") == "" {
		log.Printf("Could not resolve a PEM_PATH environment variable.")
		// os.Exit(1)
	}
		setEnvVariable("MINT_ZKP", os.Getenv("MINT_ZKP"))
	if os.Getenv("MINT_ZKP") == "" {
		log.Printf("Could not resolve a MINT_ZKP environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("TRUST_DOMAIN", os.Getenv("TRUST_DOMAIN"))
	if os.Getenv("TRUST_DOMAIN") == "" {
		log.Printf("Could not resolve a TRUST_DOMAIN environment variable.")
		// os.Exit(1)
	}
}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".cfg")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
}