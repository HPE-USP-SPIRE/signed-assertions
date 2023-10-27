package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/Assertingwl-mTLS/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
)

func ValidateDasvidHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Validate")

	dasvidexpresult := new(bool)
	dasvidsigresult := new(bool)
	var remainingtime string

	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")
	dasvidclaims := dasvid.ParseTokenClaims(datoken)
	*dasvidexpresult, remainingtime = dasvid.ValidateTokenExp(dasvidclaims)

	// Retrieve Public Key from JWKS file
	// TODO Add error handling
	pubkey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")
	// OR pubkey := dasvid.RetrievePublicKey("/keys/public.pem")

	// Verify token signature using extracted Public key
	for i := 0; i < len(pubkey.Keys); i++ {
		err := dasvid.VerifySignature(datoken, pubkey.Keys[i])
		if err == nil {
			log.Printf("Success verifying DA-SVID signature!")
			*dasvidsigresult = true
			data := models.PocData{
				DasvidExpValidation:    dasvidexpresult,
				DasvidExpRemainingTime: remainingtime,
				DasvidSigValidation:    dasvidsigresult,
				DASVIDClaims:           dasvidclaims,
			}

			json.NewEncoder(w).Encode(data)
			return
		}

		log.Printf("Error verifying DA-SVID signature!")
		*dasvidsigresult = false
		data := models.PocData{
			DasvidExpValidation:    dasvidexpresult,
			DasvidExpRemainingTime: remainingtime,
			DasvidSigValidation:    dasvidsigresult,
			DASVIDClaims:           dasvidclaims,
		}
		json.NewEncoder(w).Encode(data)
	}

	err := dasvid.VerifySignature(datoken, pubkey.Keys[0])
	if err != nil {
		log.Printf("Error verifying DA-SVID signature: %v", err)
		*dasvidsigresult = false
	} else {
		*dasvidsigresult = true
	}

	data := models.PocData{
		DasvidExpValidation:    dasvidexpresult,
		DasvidExpRemainingTime: remainingtime,
		DasvidSigValidation:    dasvidsigresult,
		DASVIDClaims:           dasvidclaims,
	}

	json.NewEncoder(w).Encode(data)
}
