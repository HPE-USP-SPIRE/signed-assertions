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

	// anonymous trace
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"crypto/x509"
	"encoding/pem"
	"crypto/ecdsa"
	"bytes"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"crypto/tls"
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
	IDArtifacts					string `json:",omitempty"`
}

type Balancetemp struct {
	User						string `json:",omitempty"`
	Balance						int `json`
	Returnmsg					string `json:",omitempty"`
}

var temp Contents

// Set curve
var curve = edwards25519.NewBlakeSHA256Ed25519()

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)

	// // If the file doesn't exist, create it, or append to the file
	// file, err := os.OpenFile("./bench.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("Writing to file...")
	// json.NewEncoder(file).Encode(fmt.Sprintf("%s execution time is %s", name, elapsed))
	// if err := file.Close(); err != nil {
	// 	log.Fatal(err)
	// }
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// validate received token and Certs
	var rcvSVID Contents

    json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received  assertion: ", rcvSVID.DASVIDToken)
	log.Print("Received SVID certs: ", rcvSVID.IDArtifacts)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID.IDArtifacts), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < len(svidcerts)-1) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(rcvSVID.DASVIDToken, ecdsakeys)
	if valid == false {
		log.Fatalf("Error validating ECDSA assertion using SVID!")
		
	}

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

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

	// Generate a new ecdsa signed assertion containing key:value with no specific audience
	// Fetch claims data
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()
	clientkey 		:= clientSVID.PrivateKey

	// generate idartifact
	tmp, _, err := clientSVID.Marshal()
	if err != nil {
		log.Fatal("Error retrieving SVID: ", err)
	}
	svidcert := strings.SplitAfter(fmt.Sprintf("%s", tmp), "-----END CERTIFICATE-----")
	idartifact := svidcert[0]
	// Updata SVID bundle 
	updSVID := strings.Trim(strings.Join([]string{rcvSVID.IDArtifacts, idartifact}, ""), "[]")
		
	// get audience 
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial("tcp", os.Getenv("TARGETWLIP"), conf)
    if err != nil {
        log.Println("Error in Dial", err)
        return
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
	audienceid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Audience SPIFFE-ID: %v", audienceid)

	// Generate assertion claims
	assertionclaims := map[string]interface{}{
		"iss"		:		clientID,
		"aud"		:		audienceid,
		"iat"		:	 	issue_time,
	}
	assertion, err := dasvid.NewECDSAencode(assertionclaims, rcvSVID.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: %s", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: %s", fmt.Sprintf("%s",idartifact))
	log.Printf("Updated SVID bundle			: %s", fmt.Sprintf("%s",updSVID))
	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
    if err != nil {
        log.Fatal(err)
    }

	endpoint := "https://"+os.Getenv("TARGETWLIP")+"/get_balance?DASVID="+assertion
	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	var tempbalance Balancetemp
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		log.Fatalf("error:", err)
	}
	json.NewEncoder(w).Encode(tempbalance)	
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "DepositHandler")
		
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// validate received token and Certs
	var rcvSVID Contents

    json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received  assertion: ", rcvSVID.DASVIDToken)
	log.Print("Received SVID certs: ", rcvSVID.IDArtifacts)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID.IDArtifacts), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < len(svidcerts)-1) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(rcvSVID.DASVIDToken, ecdsakeys)
	if valid == false {
		log.Fatalf("Error validating ECDSA assertion using SVID!")
		
	}

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

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

	// Generate a new ecdsa signed assertion containing key:value with no specific audience
	// Fetch claims data
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()
	clientkey 		:= clientSVID.PrivateKey

	// generate idartifact
	tmp, _, err := clientSVID.Marshal()
	if err != nil {
		log.Fatal("Error retrieving SVID: ", err)
	}
	svidcert := strings.SplitAfter(fmt.Sprintf("%s", tmp), "-----END CERTIFICATE-----")
	idartifact := svidcert[0]
	// Updata SVID bundle 
	updSVID := strings.Trim(strings.Join([]string{rcvSVID.IDArtifacts, idartifact}, ""), "[]")
		
	// get audience 
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial("tcp", os.Getenv("TARGETWLIP"), conf)
    if err != nil {
        log.Println("Error in Dial", err)
        return
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
	audienceid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Audience SPIFFE-ID: %v", audienceid)

	// Generate assertion claims
	assertionclaims := map[string]interface{}{
		"iss"		:		clientID,
		"aud"		:		audienceid,
		"iat"		:	 	issue_time,
	}
	assertion, err := dasvid.NewECDSAencode(assertionclaims, rcvSVID.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: %s", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: %s", fmt.Sprintf("%s",idartifact))
	log.Printf("Updated SVID bundle			: %s", fmt.Sprintf("%s",updSVID))
	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
    if err != nil {
        log.Fatal(err)
    }

	// Gera chamada para target workload 
	endpoint := "https://"+os.Getenv("TARGETWLIP")+"/deposit?DASVID="+r.FormValue("DASVID")+"&deposit="+r.FormValue("deposit")

	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	var tempbalance Balancetemp
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