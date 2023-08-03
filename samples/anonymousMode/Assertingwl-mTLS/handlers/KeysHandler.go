package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Keys endpoint")

	rsaPublicKey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")

	json.NewEncoder(w).Encode(rsaPublicKey)

}
