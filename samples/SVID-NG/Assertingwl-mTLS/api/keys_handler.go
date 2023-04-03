package api

import (
	"net/http"
	"encoding/json"
	"time"
	
	dasvid "SVID-NG/poclib"
	"SVID-NG/utils" 
)


func KeysHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Keys endpoint")

	rsaPublicKey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")

	json.NewEncoder(w).Encode(rsaPublicKey)
	
}