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

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/Assertingwl-mTLS/models"
	// "github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/global"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func MintAssertionHandler(w http.ResponseWriter, r *http.Request) {

	var fileTemp models.FileContents
	var Data models.PocData

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
		Data := models.PocData{
			OauthExpValidation:		expresult,
			OauthExpRemainingTime:	remainingtime,
		}
		json.NewEncoder(w).Encode(Data)
	} else {
		// Retrieve Public Key from JWKS endpoint
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
				log.Printf("Success verifying OAuth Token signature!")
				break
			}
			if i == len(pubkey.Keys)-1 {
				log.Printf("Error verifying OAuth Token signature: %v", err)
				*sigresult = false
				Data := models.PocData{
					OauthExpValidation:		expresult,
					OauthExpRemainingTime:	remainingtime,
					OauthSigValidation:		sigresult,
				}
				json.NewEncoder(w).Encode(Data)
				return
			}
		}

		*sigresult = true
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
		
		// save just signature.R due to concatenation process
		// Retrieve signature from originaltoken 
		parts := strings.Split(assertion, ".")	
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

		fileTemp = models.FileContents{
			OauthToken:					oauthtoken,
			DASVIDToken:	 			assertionlkp,
		}

		// Data to be returned in API 
		Data = models.PocData{
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
		json.NewEncoder(file).Encode(fileTemp)
		if err := file.Close(); err != nil {
			log.Fatal(err)
		}
	}
	json.NewEncoder(w).Encode(Data)
}