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
	// "github.com/hpe-usp-spire/signed-assertions/IDMode/api-libs/global"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

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

	var FileTemp models.FileContents
	var Data models.PocData
	if *expresult == false {
		log.Printf("Oauth token expired!")
	
		Data := models.PocData{
			OauthExpValidation:    expresult,
			OauthExpRemainingTime: remainingtime,
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
	for i := 0; i < len(pubkey.Keys); i++ {

		err := dasvid.VerifySignature(oauthtoken, pubkey.Keys[i])
		if err == nil {
			log.Printf("Success verifying DA-SVID signature!")
			break
		}

		if i == len(pubkey.Keys)-1 {
			log.Printf("Error verifying OAuth signature: %v", err)
			*sigresult = false

			Data := models.PocData{
				OauthExpValidation:    expresult,
				OauthExpRemainingTime: remainingtime,
				OauthSigValidation:    sigresult,
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
		FileTemp = models.FileContents{
			OauthToken:  oauthtoken,
			DASVIDToken: assertion,
		}

		// Data to be returned in API ++
		Data = models.PocData{
			OauthSigValidation:    sigresult,
			OauthExpValidation:    expresult,
			OauthExpRemainingTime: remainingtime,
			DASVIDToken:           assertion,
			IDArtifacts:		   idartifact,
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
	}
		json.NewEncoder(w).Encode(Data)
}
