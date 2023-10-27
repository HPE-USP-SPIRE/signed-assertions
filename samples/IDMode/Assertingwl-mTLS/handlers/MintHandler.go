package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/Assertingwl-mTLS/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func MintHandler(w http.ResponseWriter, r *http.Request) {

	var FileTemp models.FileContents
	var Data models.PocData
	// MODIFICATIONS TO BENCHMARK THE SOLUTION. REMOVE AFTER
	for i := 0; i < 1; i++ {
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

			Data = models.PocData{
				OauthExpValidation:    expresult,
				OauthExpRemainingTime: remainingtime,
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
			for i := 0; i < len(pubkey.Keys); i++ {

				err := dasvid.VerifySignature(oauthtoken, pubkey.Keys[i])
				if err == nil {
					log.Printf("Success verifying DA-SVID signature!")
					break
				}

				if i == len(pubkey.Keys)-1 {
					log.Printf("Error verifying OAuth signature: %v", err)
					*sigresult = false

					Data = models.PocData{
						OauthExpValidation:    expresult,
						OauthExpRemainingTime: remainingtime,
						OauthSigValidation:    sigresult,
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
				FileTemp = models.FileContents{
					OauthToken:  oauthtoken,
					DASVIDToken: token,
					ZKP:         zkp,
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
				FileTemp = models.FileContents{
					OauthToken:  oauthtoken,
					DASVIDToken: token,
				}
			}

			// Data to be returned in API
			Data = models.PocData{
				OauthSigValidation:    sigresult,
				OauthExpValidation:    expresult,
				OauthExpRemainingTime: remainingtime,
				DASVIDToken:           token,
			}

			// If the file doesn't exist, create it, or append to the file
			file, err := os.OpenFile("./data/dasvid.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Writing to file...")
			json.NewEncoder(file).Encode(FileTemp)
			if err := file.Close(); err != nil {
				log.Fatal(err)
			}

			json.NewEncoder(w).Encode(Data)
		}
	}
}

// private functions

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
