package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/models"
    "github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/local"
)

var (
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
)

// var (
// 	tpl          *template.Template
// 	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
// 	state        = generateState()
// 	nonce        = "NonceNotSetYet"
// 	// Set curve
// 	curve = edwards25519.NewBlakeSHA256Ed25519()
// )

var temp models.Contents
var oktaclaims map[string]interface{}
var dasvidclaims map[string]interface{}
var Data models.PocData

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])

	fmt.Printf("local.Options: %v", local.Options)

	Data = models.PocData{
		AppURI:          local.Options.HostIP,
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:      haveDASVID(),
		AccessToken:     strAT,
	}

	local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func haveDASVID() bool {

	if os.Getenv("DASVIDToken") == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {

	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}
