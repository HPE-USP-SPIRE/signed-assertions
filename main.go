//+build linux,cgo 
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
	
	"strings"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"context"
	"io"
	"time"
	"io/ioutil"
	"crypto/x509"
    "encoding/pem"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	
	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"

)

type FileContents struct {
	OauthToken					string `json:OauthToken",omitempty"`
	Msg							[]byte `json:Msg",omitempty"`
	DASVIDToken					string `json:DASVIDToken",omitempty"`
	ZKP							string `json:ZKP",omitempty"`
}

type PocData struct {
	AccessToken     			string `json:",omitempty"`
	PublicKey					string `json:",omitempty"`
	OauthSigValidation 			*bool `json:",omitempty"`
	OauthExpValidation 			*bool `json:",omitempty"`
	OauthExpRemainingTime		string `json:",omitempty"`
	OauthClaims					map[string]interface{} `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
	DASVIDClaims 				map[string]interface{} `json:",omitempty"`
	DasvidExpValidation 		*bool `json:",omitempty"`
	DasvidExpRemainingTime		string `json:",omitempty"`
	DasvidSigValidation 		*bool `json:",omitempty"`
}

var Data PocData
var Filetemp FileContents

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func main() {

	// Parse environment for asserting workload main
	dasvid.ParseEnvironment(1)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/mint", MintHandler)
	http.HandleFunc("/keys", KeysHandler)
	http.HandleFunc("/validate", ValidateDasvidHandler)
	http.HandleFunc("/introspect", IntrospectHandler)
	http.HandleFunc("/assert", AssertHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Printf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - In PoC, Clients must be from the same trust domain
	// 
	// TODO: Could be interesting to add this in config file
	// 
	clientID := spiffeid.RequireTrustDomainFromString("example.org")
	
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

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Keys endpoint")

	rsaPublicKey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")

	json.NewEncoder(w).Encode(rsaPublicKey)
	
}

func MintHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Mint endpoint")

	sigresult := new(bool)
	expresult := new(bool)
	var remainingtime, zkp string

	certs := r.TLS.PeerCertificates

	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Client SPIFFE-ID: %v", clientspiffeid)

	oauthtoken := r.FormValue("AccessToken")
	tokenclaims := dasvid.ParseTokenClaims(oauthtoken)
	issuer := fmt.Sprintf("%v", tokenclaims["iss"])
	uri, result := dasvid.ValidateISS(issuer)
	if result != true {
		log.Fatal("OAuth token issuer not identified!")
	}

	*expresult, remainingtime = dasvid.ValidateTokenExp(tokenclaims)

	if *expresult == false {

		log.Printf("Oauth token expired!")

		Data = PocData{
			OauthExpValidation:		expresult,
			OauthExpRemainingTime:  remainingtime,
		}
		json.NewEncoder(w).Encode(Data)

	} else {

		// Retrieve Public Key from JWKS endpoint
		// 
		log.Println("OAuth Issuer: ", tokenclaims["iss"])

		// Retrieve and save OAuth JWKS public key in cache file
		resp, err := http.Get(uri)
		defer resp.Body.Close()
		// Save response in cache file
		// TODO:
		// If the file exists it reuse or overwrite? It could be an old key...
		out, err := os.Create("./data/oauthjwkskey.cache")
		if err != nil {
			log.Printf("Error creating Oauth public key cache file: %v", err)
		}
		defer out.Close()
		io.Copy(out, resp.Body)

		// Read key from cache file
		pubkey := dasvid.RetrieveJWKSPublicKey("./data/oauthjwkskey.cache")

		// Verify token signature using extracted Public key
		// //////////////////////////////////
		// TODO: create loop to test all keys in file
		//////////////////////////////////////
		err = dasvid.VerifySignature(oauthtoken, pubkey.Keys[0])
		if err != nil {

			log.Printf("Error verifying OAuth signature: %v", err)
			*sigresult = false

			Data = PocData{
				OauthExpValidation:		expresult,
				OauthExpRemainingTime:  remainingtime,
				OauthSigValidation:		sigresult,
			}

			json.NewEncoder(w).Encode(Data)
			
		} else {

			*sigresult = true

			// Fetch Asserting workload SVID to use as DASVID issuer
			assertingwl := dasvid.FetchX509SVID()

			// Gen ZKP
			// 
			// About format:
			// received proof = json containing proof P and C arrays
			// 
			// validation: 
			// - gen vkey and extract bigN and bigE 
			// - verifyhexproof(json proof, msg, vkey) 
			// 

			// Load private key from pem file used to sign DASVID
			awprivatekey := dasvid.RetrievePrivateKey("./keys/key.pem")

			var token string
			
			if os.Getenv("MINT_ZKP") == "true" {

				parts := strings.Split(oauthtoken, ".")
				message := []byte(strings.Join(parts[0:2], "."))

				// Generate DASVID claims
				iss := assertingwl.ID.String()
				sub := clientspiffeid.String()
				dpa := fmt.Sprintf("%v", issuer)
				dpr := fmt.Sprintf("%v", tokenclaims["sub"])
				oam := message
				zkp = dasvid.GenZKPproof(oauthtoken)
				if zkp == "" {
					log.Println("Error generating ZKP proof")
				}

				// Generate DASVID
				token = dasvid.Mintdasvid(iss, sub, dpa, dpr, oam, zkp, awprivatekey)
				log.Printf("DA-SVID generated: ", token)

				// Data to be write in cache file
				Filetemp = FileContents{
					OauthToken:					oauthtoken,
					DASVIDToken:	 			token,
					ZKP:						zkp,						
				}
				
			} else {
				
				// Generate DASVID claims
				iss := assertingwl.ID.String()
				sub := clientspiffeid.String()
				dpa := fmt.Sprintf("%v", issuer)
				dpr := fmt.Sprintf("%v", tokenclaims["sub"])

				// Generate DASVID
				token = dasvid.Mintdasvid(iss, sub, dpa, dpr, nil, "", awprivatekey)
				log.Printf("DA-SVID generated: ", token)

				// Data to be write in cache file
				Filetemp = FileContents{
					OauthToken:					oauthtoken,
					DASVIDToken:	 			token,
				}
			}

			// Data to be returned in API 
			Data = PocData{
				OauthSigValidation: 		sigresult,
				OauthExpValidation:			expresult,
				OauthExpRemainingTime:  	remainingtime,
				DASVIDToken:	 			token,
			}

			// If the file doesn't exist, create it, or append to the file
			file, err := os.OpenFile("./data/dasvid.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Writing to file...")
			json.NewEncoder(file).Encode(Filetemp)
			if err := file.Close(); err != nil {
				log.Fatal(err)
			}

			json.NewEncoder(w).Encode(Data)
		}
	}
}

func ValidateDasvidHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Validate")
	
	dasvidexpresult := new(bool)
	dasvidsigresult := new(bool)
	var remainingtime  string
	
	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")
	dasvidclaims := dasvid.ParseTokenClaims(datoken)
	*dasvidexpresult, remainingtime = dasvid.ValidateTokenExp(dasvidclaims)

	// Retrieve Public Key from JWKS file
	// TODO Add error handling
	pubkey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")
	// OR pubkey := dasvid.RetrievePublicKey("/keys/public.pem")

	// Verify token signature using extracted Public key
	err := dasvid.VerifySignature(datoken, pubkey.Keys[0])
	if err != nil {
		log.Printf("Error verifying DA-SVID signature: %v", err)
		*dasvidsigresult = false
	} else {
		*dasvidsigresult = true
	}
	
	Data = PocData{
		DasvidExpValidation: 	dasvidexpresult,
		DasvidExpRemainingTime: remainingtime,
		DasvidSigValidation:	dasvidsigresult,
		DASVIDClaims:			dasvidclaims,
	}

	json.NewEncoder(w).Encode(Data)
}

func IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Introspect endpoint")

	var zkp string
	
	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")

	// // Open dasvid cache file
	datafile, err := ioutil.ReadFile("./data/dasvid.data")
	if err != nil {
			log.Fatalln(err)
	}

	// // Iterate over lines looking for DASVID token
	lines := strings.Split(string(datafile), "\n")

	for i := range lines {

		json.Unmarshal([]byte(lines[i]), &Filetemp)
		if err != nil {
			log.Printf("error:", err)
		}

		if Filetemp.DASVIDToken == datoken {
			log.Println("DASVID token identified!")
			
			parts := strings.Split(Filetemp.OauthToken, ".")
			message := []byte(strings.Join(parts[0:2], "."))
			
			if Filetemp.ZKP == "" {
				log.Println("No ZKP identified! Generating one...")

				zkp = dasvid.GenZKPproof(Filetemp.OauthToken)
				if zkp == "" {
					log.Println("Error generating ZKP proof")
				}

				Filetemp = FileContents{
					OauthToken:					Filetemp.OauthToken,
					DASVIDToken:	 			datoken,
					Msg:						message,
					ZKP:						zkp,
				}

				tmpstr, _ := json.Marshal(Filetemp)
				err = ioutil.WriteFile("./data/dasvid.data", []byte(string(tmpstr)), 0644)
				if err != nil {
						log.Fatalln(err)
				}

				Filetemp = FileContents{
					Msg:						message,
					ZKP:						zkp,
				}

			} else { 
				log.Println("Previous ZKP identified!")
				zkp = Filetemp.ZKP 

				Filetemp = FileContents{
					Msg:			message,
					ZKP:			Filetemp.ZKP,
				}
			}			
			json.NewEncoder(w).Encode(Filetemp)
			return
		}
    }
	json.NewEncoder(w).Encode("DASVID not found")
}

func AssertHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Assert")

	certs := r.TLS.PeerCertificates
	// clientspiffeid, err := x509svid.IDFromCert(certs[0])
	clientpubkey, _ := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: clientpubkey,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	fmt.Println("TODO: persistir public key: %s", publicKeyPem)

	clientID := r.FormValue("clientID")
	clientkey := r.FormValue("clientkey")
	datoken := r.FormValue("DASVID")	
	// tokenclaims := dasvid.ParseTokenClaims(datoken)
	// issuer := fmt.Sprintf("%v", tokenclaims["iss"])
	next := r.FormValue("next")

	// Load private key from pem file used to sign DASVID
	// awprivatekey := dasvid.RetrievePrivateKey("./keys/key.pem")
	
	// Generate DASVID
	token := dasvid.MintAssertion(clientID, next, datoken, clientkey)
	
	json.NewEncoder(w).Encode(token)
	
}

