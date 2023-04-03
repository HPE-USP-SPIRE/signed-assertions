package api

import (
	"net/http"
	"log"
	"encoding/json"
	"time"

	
	dasvid "SVID-NG/poclib"
	"SVID-NG/types"
	"SVID-NG/utils" 
)



func ValidateDasvidHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Validate")
	
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
			Data = types.PocData{
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
		Data = types.PocData{
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
	
	Data = types.PocData{
		DasvidExpValidation: 	dasvidexpresult,
		DasvidExpRemainingTime: remainingtime,
		DasvidSigValidation:	dasvidsigresult,
		DASVIDClaims:			dasvidclaims,
	}

	json.NewEncoder(w).Encode(Data)
}