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
	"bufio"
	"io/ioutil"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	
	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"

	// "crypto/ecdsa"

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
	IDArtifacts					string `json:",omitempty"`
}

var Data PocData
var Filetemp FileContents

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

	// Parse environment for asserting workload main
	ParseEnvironment()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/mint", MintHandler)
	http.HandleFunc("/keys", KeysHandler)
	http.HandleFunc("/validate", ValidateDasvidHandler)
	http.HandleFunc("/introspect", IntrospectHandler)
	// 
	http.HandleFunc("/mintassertion", MintAssertionHandler)
	http.HandleFunc("/ecdsaassertion", ECDSAAssertionHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Printf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - In PoC, Clients must be from the same trust domain
	// 
	clientID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))
	
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
	// MODIFICATIONS TO BENCHMARK THE SOLUTION. REMOVE AFTER
	for i:=0; i<1; i++ {
		log.Printf("Execution number: %v", i)
		defer timeTrack(time.Now(), fmt.Sprintf("Mint endpoint execution number: %v", i))

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
			issuer := fmt.Sprintf("%v", tokenclaims["iss"])
			log.Println("OAuth Issuer: ", issuer)
			uri, result := dasvid.ValidateISS(issuer)
			if result != true {
				log.Fatal("OAuth token issuer not identified!")
			}

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
			for i :=0; i<len(pubkey.Keys); i++ {

				err := dasvid.VerifySignature(oauthtoken, pubkey.Keys[i])
				if err == nil {
					log.Printf("Success verifying DA-SVID signature!")
					break
				} 

				if i == len(pubkey.Keys)-1 {
					log.Printf("Error verifying OAuth signature: %v", err)
					*sigresult = false
		
					Data = PocData{
						OauthExpValidation:		expresult,
						OauthExpRemainingTime:  remainingtime,
						OauthSigValidation:		sigresult,
					}
				
					json.NewEncoder(w).Encode(Data)
					return
				}
			}
				
			*sigresult = true
			

			// Fetch Asserting workload SVID to use as DASVID issuer
			assertingwl := dasvid.FetchX509SVID()

			// ZKP
			// format: received proof = json containing proof P and C arrays
			// 
			// validation: 
			// - generate vkey with token2vkey or other and extract bigN and bigE 
			// - verifyhexproof(json proof, msg, vkey) 

			// Load private key from pem file used to sign DASVID
			awprivatekey := dasvid.RetrievePrivateKey("./keys/key.pem")
			
			// Load public key to extract kid
			pubkey = dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")
			fmt.Println("key ", pubkey.Keys[0])
			kid := pubkey.Keys[0].Kid
			var token string
			
			if os.Getenv("MINT_ZKP") == "true" {
				log.Printf("Generating ZKP...")

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

				if os.Getenv("ADD_ZKP") == "true" {
					log.Printf("Adding ZKP into DASVID...")
					// Generate DASVID
					token = dasvid.Mintdasvid(kid, iss, sub, dpa, dpr, oam, zkp, awprivatekey)
				} else {
					token = dasvid.Mintdasvid(kid, iss, sub, dpa, dpr, nil, "", awprivatekey)
				}

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
				token = dasvid.Mintdasvid(kid, iss, sub, dpa, dpr, nil, "", awprivatekey)


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
	for i :=0; i<len(pubkey.Keys); i++ {
		err := dasvid.VerifySignature(datoken, pubkey.Keys[i])
		if err == nil {
			log.Printf("Success verifying DA-SVID signature!")
			*dasvidsigresult = true
			Data = PocData{
				DasvidExpValidation: 	dasvidexpresult,
				DasvidExpRemainingTime: remainingtime,
				DasvidSigValidation:	dasvidsigresult,
				DASVIDClaims:			dasvidclaims,
			}
		
			json.NewEncoder(w).Encode(Data)
			return
		} 
		
		log.Printf("Error verifying DA-SVID signature!")
		*dasvidsigresult = false
		Data = PocData{
			DasvidExpValidation: 	dasvidexpresult,
			DasvidExpRemainingTime: remainingtime,
			DasvidSigValidation:	dasvidsigresult,
			DASVIDClaims:			dasvidclaims,
		}
		json.NewEncoder(w).Encode(Data)
	}

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
					lines[i] = string(tmpstr)
					datafile = []byte(strings.Join(lines, "\n"))
					err := ioutil.WriteFile("./data/dasvid.data", datafile, 0644)					
					if err != nil {
							log.Fatalln(err)
					}

					Filetemp = FileContents{
						Msg:	message,
						ZKP:	zkp,
					}

				} else { 
					log.Println("Previous ZKP identified!")
					zkp = Filetemp.ZKP 

					Filetemp = FileContents{
						Msg:	message,
						ZKP:	Filetemp.ZKP,
					}
				}			
				json.NewEncoder(w).Encode(Filetemp)
				return
			}
		}
		json.NewEncoder(w).Encode("DASVID not found")
}

func MintAssertionHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("MintAssertionHandler Execution")
	defer timeTrack(time.Now(), fmt.Sprintf("MintAssertionHandler Execution"))
	sigresult := new(bool)
	expresult := new(bool)
	var remainingtime string
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Client SPIFFE-ID: %v", clientspiffeid)
	oauthtoken := r.FormValue("AccessToken")
	tokenclaims := dasvid.ParseTokenClaims(oauthtoken)
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
		oauthissuer := fmt.Sprintf("%v", tokenclaims["iss"])
		log.Println("OAuth Issuer: ", oauthissuer)
		uri, result := dasvid.ValidateISS(oauthissuer)
		if result != true {
			log.Fatal("OAuth token issuer not identified!")
		}
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
		for i :=0; i<len(pubkey.Keys); i++ {
			err := dasvid.VerifySignature(oauthtoken, pubkey.Keys[i])
			if err == nil {
				log.Printf("Success verifying oauth token signature!")
				break
			} 
			if i == len(pubkey.Keys)-1 {
				log.Printf("Error verifying oauth token signature: %v", err)
				*sigresult = false
	
				Data = PocData{
					OauthExpValidation:		expresult,
					OauthExpRemainingTime:  remainingtime,
					OauthSigValidation:		sigresult,
				}
			
				json.NewEncoder(w).Encode(Data)
				return
			}
		}
			
		*sigresult = true

		// Generate a new schnorr signed assertion containing key:value with no specific audience

		// Generate Keypair
		privateKey, publicKey := dasvid.RandomKeyPair()
		// fmt.Println("Generated publicKey: ", publicKey)

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			log.Fatal("Error decoding point string!")
		} 

		// Generate assertion claims
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"aud"		:		clientspiffeid.String(),
			"iat"		:	 	issue_time,
			"dpa"		:		fmt.Sprintf("%v", oauthissuer),
			"dpr"		:		fmt.Sprintf("%v", tokenclaims["sub"]),	
		}

		assertion, err := dasvid.NewSchnorrencode(assertionclaims, "", privateKey)
		if err != nil {
			log.Fatal("Error generating signed schnorr assertion!")
		} 

		log.Printf("Generated assertion: ", fmt.Sprintf("%s",assertion))



		// Data to be writen in cache file

		// save just signature.R due to concatenation process
				// Retrieve signature from originaltoken 
				parts 			:= strings.Split(assertion, ".")	
				prevsignature, err := dasvid.String2schsig(parts[1])
				if err != nil {
					fmt.Println("Error converting string to schnorr signature!")
					os.Exit(1)
				} 
				// Discard sig.S
				parts[1], err = dasvid.Point2string(prevsignature.R)
				if err != nil {
					fmt.Println("Error decoding point string!")
					os.Exit(1)
				} 
				assertionlkp := strings.Join(parts, ".")

		Filetemp = FileContents{
			OauthToken:					oauthtoken,
			DASVIDToken:	 			assertionlkp,
		}

		// Data to be returned in API 
		Data = PocData{
			OauthSigValidation: 		sigresult,
			OauthExpValidation:			expresult,
			OauthExpRemainingTime:  	remainingtime,
			DASVIDToken:	 			assertion,
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
	}
		json.NewEncoder(w).Encode(Data)
}

func ECDSAAssertionHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("ECDSAAssertionHandler Execution")
	defer timeTrack(time.Now(), fmt.Sprintf("ECDSAAssertionHandler Execution"))
	sigresult := new(bool)
	expresult := new(bool)
	var remainingtime string
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Client SPIFFE-ID: %v", clientspiffeid)
	oauthtoken := r.FormValue("AccessToken")
	tokenclaims := dasvid.ParseTokenClaims(oauthtoken)
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
		oauthissuer := fmt.Sprintf("%v", tokenclaims["iss"])
		log.Println("OAuth Issuer: ", oauthissuer)
		uri, result := dasvid.ValidateISS(oauthissuer)
		if result != true {
			log.Fatal("OAuth token issuer not identified!")
		}
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
		for i :=0; i<len(pubkey.Keys); i++ {
			err := dasvid.VerifySignature(oauthtoken, pubkey.Keys[i])
			if err == nil {
				log.Printf("Success verifying oauth token signature!")
				break
			} 
			if i == len(pubkey.Keys)-1 {
				log.Printf("Error verifying oauth token signature: %v", err)
				*sigresult = false
	
				Data = PocData{
					OauthExpValidation:		expresult,
					OauthExpRemainingTime:  remainingtime,
					OauthSigValidation:		sigresult,
				}
			
				json.NewEncoder(w).Encode(Data)
				return
			}
		}
			
		*sigresult = true

		// Generate a new ecdsa signed assertion containing key:value with no specific audience

		
		// Fetch claims data
		clientSVID 		:= dasvid.FetchX509SVID()
		clientID 		:= clientSVID.ID.String()
		clientkey 		:= clientSVID.PrivateKey

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// generate idartifact
			// Uses SVID cert bundle as ISSUER
			tmp, _, err := clientSVID.Marshal()
			if err != nil {
				fmt.Println("Error retrieving SVID: ", err)
				os.Exit(1)
			}
			svidcert := strings.SplitAfter(fmt.Sprintf("%s", tmp), "-----END CERTIFICATE-----")

			idartifact := svidcert[0]

		// Generate assertion claims
		assertionclaims := map[string]interface{}{
			"iss"		:		clientID,
			"aud"		:		clientspiffeid.String(),
			"iat"		:	 	issue_time,
			"dpa"		:		fmt.Sprintf("%v", oauthissuer),
			"dpr"		:		fmt.Sprintf("%v", tokenclaims["sub"]),	
		}

		assertion, err := dasvid.NewECDSAencode(assertionclaims, "", clientkey)
		if err != nil {
			log.Fatal("Error generating signed ECDSA assertion!")
		} 

		log.Printf("Generated ECDSA assertion: ", fmt.Sprintf("%s",assertion))



		// Data to be writen in cache file
		Filetemp = FileContents{
			OauthToken:					oauthtoken,
			DASVIDToken:	 			assertion,
		}

		// Data to be returned in API 
		Data = PocData{
			OauthSigValidation: 		sigresult,
			OauthExpValidation:			expresult,
			OauthExpRemainingTime:  	remainingtime,
			DASVIDToken:	 			assertion,
			IDArtifacts:				idartifact,
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
	}
		json.NewEncoder(w).Encode(Data)
}


func ParseEnvironment() {

	if _, err := os.Stat(".cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
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

	setEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
		// os.Exit(1)
	}
	
	setEnvVariable("TRUST_DOMAIN", os.Getenv("TRUST_DOMAIN"))
	if os.Getenv("TRUST_DOMAIN") == "" {
		log.Printf("Could not resolve a TRUST_DOMAIN environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("ADD_ZKP", os.Getenv("ADD_ZKP"))
	if os.Getenv("ADD_ZKP") == "" {
		log.Printf("Could not resolve a ADD_ZKP environment variable.")
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

