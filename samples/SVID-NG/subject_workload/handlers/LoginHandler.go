package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Login")

	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	// Retrieve local IP
	// Must be authorized in OKTA configuration.
	// Hard coded here to allow the redirection to subj wl container
	uri := "http://" + os.Getenv("HOSTIP") + "/callback"
	fmt.Println("URI: ", uri)

	nonce, _ = oktaUtils.GenerateNonce()
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")  // code or token
	q.Add("response_mode", "query") // query or fragment
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", uri)
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s execution time is %s", name, elapsed)
}
