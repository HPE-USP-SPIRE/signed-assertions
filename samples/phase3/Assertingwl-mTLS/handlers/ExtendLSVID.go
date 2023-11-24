package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/Assertingwl-mTLS/local"
	"github.com/hpe-usp-spire/signed-assertions/phase3/Assertingwl-mTLS/models"
	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	// LSVID pkg
	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
)

// Receives workload LSVID and an OAuth token, extending the LSVID with delegation claims.
// Inputs: Oauth token, caller LSVID
// Output: Extended LSVID with OAuth claims
func ExtendLSVIDHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), fmt.Sprintf("ExtendLSVIDHandler Execution"))
	
	local.InitGlobals()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigresult := new(bool)
	expresult := new(bool)
	var remainingtime string

	// Retrieve caller cert and spiffe-id
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Client SPIFFE-ID: %v", clientspiffeid)

	// Validate OAuth token expiration
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
		// If not expired, validate the signature

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

		// If reached here, the OAuth is valid and we can proceed to LSVID extension

		// Fetch asserting workload data
		assertingSVID 		:= dasvid.FetchX509SVID()
		assertingID 		:= assertingSVID.ID.String()
		assertingKey 		:= assertingSVID.PrivateKey

		// Fetch asserting workload LSVID
		assertingLSVID, err := lsvid.FetchLSVID(ctx, local.Options.SocketPath)
		if err != nil {
			log.Fatalf("Error fetching LSVID: %v\n", err)
		}

		// decode asserting wl  LSVID
		decAsserting, err := lsvid.Decode(assertingLSVID)
		if err != nil {
			log.Fatalf("Unable to decode LSVID %v\n", err)
		}

		extendedPayload := &lsvid.Payload{
			Ver:	1,
			Alg:	"ES256",
			Iat:	time.Now().Round(0).Unix(),
			Iss:	&lsvid.IDClaim{
				CN:	assertingID,
				ID:	decAsserting.Token,
			},
			Aud:	&lsvid.IDClaim{
				CN:	clientspiffeid.String(),
			},
			Dpa:	fmt.Sprintf("%v", oauthissuer),
			Dpr:	fmt.Sprintf("%v", tokenclaims["sub"]),	
		}

		
		// TODO: Check the best way to foward the LSVID (in the formvalue, in the body or other...)
		callerLSVID := r.FormValue("LSVID")

		// decode received LSVID
		decRecLSVID, err := lsvid.Decode(callerLSVID)
		if err != nil {
			log.Fatalf("Unable to decode LSVID %v\n", err)
		}

		extendedLSVID, err := lsvid.Extend(decRecLSVID, extendedPayload, assertingKey)
		if err != nil {
			log.Fatal("Error extending LSVID: %v\n", err)
		} 

		log.Printf("Extended LSVID: ", fmt.Sprintf("%s",extendedLSVID))



		// Data to be writen in cache file (associates a specific OAuth to an LSVID)
		FileTemp = models.FileContents{
			OauthToken:  oauthtoken,
			DASVIDToken: extendedLSVID,
		}

		// Data to be returned in API
		Data = models.PocData{
			OauthSigValidation:    sigresult,
			OauthExpValidation:    expresult,
			OauthExpRemainingTime: remainingtime,
			DASVIDToken:           extendedLSVID,
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
		log.Printf("Data:%v",Data)
		json.NewEncoder(w).Encode(Data)
}
