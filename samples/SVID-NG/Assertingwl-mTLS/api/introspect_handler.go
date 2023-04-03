//+build linux,cgo 
package api
/*
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "../poclib/rsa_sig_proof.h"
#include "../poclib/rsa_bn_sig.h"
#include "../poclib/rsa_sig_proof_util.h"

#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}

*/
import "C"

import (
	"net/http"
	"log"
	"encoding/json"
	"time"
	"fmt"
	"strings"
	"io/ioutil"
	
	dasvid "SVID-NG/poclib"
	"SVID-NG/types"
	"SVID-NG/utils" 
)

var Data types.PocData
var Filetemp types.FileContents

func IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Introspect endpoint")
		var zkp string
		var keyjson []byte
		
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
				log.Printf("Key %d not match...", i)
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

					pubkey := dasvid.RetrieveJWKSPublicKey("./keys/oauth.json")
					
					// Verify token signature using extracted Public key
					for i :=0; i<len(pubkey.Keys); i++ {
				
						err := dasvid.VerifySignature(Filetemp.OauthToken, pubkey.Keys[i])
						if err != nil {
							log.Printf("Key %d not match...", i)
						} else {
							log.Printf("Key found!")
							keyjson, err = json.Marshal(pubkey.Keys[i])
							if err != nil {
								fmt.Println("error:", err)
								return
							}
							log.Printf("Generated pubkey to future use: %s", string(keyjson))

							Filetemp = types.FileContents{
								OauthToken:					Filetemp.OauthToken,
								DASVIDToken:	 			datoken,
								Msg:						message,
								ZKP:						zkp,
								PubKey:						keyjson,
							}

							tmpstr, _ := json.Marshal(Filetemp)
							lines[i] = string(tmpstr)
							datafile = []byte(strings.Join(lines, "\n"))
							err := ioutil.WriteFile("./data/dasvid.data", datafile, 0644)					
							if err != nil {
									log.Fatalln(err)
							}

							Filetemp = types.FileContents{
								Msg:		message,
								ZKP:		zkp,
								PubKey:		keyjson,
							}
							json.NewEncoder(w).Encode(Filetemp)
							return
						}
					}
				} else { 
					log.Println("Previous ZKP identified!")
					zkp = Filetemp.ZKP 

					Filetemp = types.FileContents{
						Msg:	message,
						ZKP:	Filetemp.ZKP,
						PubKey:	Filetemp.PubKey,
					}
				}			
				json.NewEncoder(w).Encode(Filetemp)
				return
			}
		}
		json.NewEncoder(w).Encode("DASVID not found")
}