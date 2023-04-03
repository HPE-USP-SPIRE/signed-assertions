package api

import (

	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib test
	dasvid "github.com/marco-developer/dasvid/poclib"

	// To sig. validation 
	_ "crypto/sha256"
	
	// Okta
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"

	"SVID-NG/utils"
	"SVID-NG/types"
)

var (
	state        = utils.GenerateState()
	nonce        = "NonceNotSetYet"
	temp			types.PocData
)

func init() {
    utils.Tpl = template.Must(template.ParseGlob("./templates/*"))
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	session, err := utils.SessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	
	utils.Data = types.PocData{
		AppURI:			 os.Getenv("HOSTIP"),
		Profile:         getProfileData(r),
		IsAuthenticated: utils.IsAuthenticated(r),
		HaveDASVID:		 utils.HaveDASVID(),
		AccessToken:	 strAT,
	}

	utils.Tpl.ExecuteTemplate(w, "home.gohtml", utils.Data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Login")

	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20
	
	// Retrieve local IP
	// Must be authorized in OKTA configuration.
	// Hard coded here to allow the redirection to subj wl container
	uri := "http://" + os.Getenv("HOSTIP") + "/callback"
	fmt.Println("URI: ", uri )
	
	nonce, _ = oktaUtils.GenerateNonce()
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code") // code or token
	q.Add("response_mode", "query") // query or fragment
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", uri)
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Callback Handler")

	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		return
	}

	session, err := utils.SessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		log.Fatal(verificationError)
	}

	os.Setenv("oauthtoken", exchange.AccessToken)

	session.Values["id_token"] = exchange.IdToken
	session.Values["access_token"] = exchange.AccessToken
	session.Save(r, w)
	
	log.Printf("New login detected!")

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Profile Handler")

	utils.Data = types.PocData{
		AppURI:			 os.Getenv("HOSTIP"),
		Profile:         getProfileData(r),
		IsAuthenticated: utils.IsAuthenticated(r),
		HaveDASVID:		 utils.HaveDASVID(),
	}
	utils.Tpl.ExecuteTemplate(w, "profile.gohtml", utils.Data)
}

func AccountHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Account Handler")

	log.Print("Contacting Assertingwl to retrieve DA-SVID... ")

	receivedDASVID := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedDASVID), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received DA-SVID: ", receivedDASVID)

	if (*temp.OauthSigValidation == false) || (*temp.OauthExpValidation == false) {

		returnmsg := "Oauth token validation error"

		utils.Data = types.PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		utils.IsAuthenticated(r),
			Returnmsg: 				returnmsg,
		}

		log.Printf(returnmsg)
		utils.Tpl.ExecuteTemplate(w, "home.gohtml", utils.Data)

	} else {

		os.Setenv("DASVIDToken", temp.DASVIDToken)

		dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))

		utils.Data = types.PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		utils.IsAuthenticated(r),
			DASVIDToken:			temp.DASVIDToken,
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				utils.HaveDASVID(),
			OauthSigValidation: 	temp.OauthSigValidation,
			OauthExpValidation:		temp.OauthExpValidation,
		}

		utils.Tpl.ExecuteTemplate(w, "account.gohtml", utils.Data)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := utils.SessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	delete(session.Values, "DASVIDToken")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) types.Exchange {
	defer utils.TimeTrack(time.Now(), "Exchange OKTA Oauth code")

	var exchange types.Exchange

	// Retrieve local IP
	uri := "http://" + os.Getenv("HOSTIP") + "/callback"

	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", uri)

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	json.Unmarshal(body, &exchange)

	return exchange
}

func getProfileData(r *http.Request) map[string]string {

	m := make(map[string]string)

	session, err := utils.SessionStore.Get(r, "okta-hosted-login-session-store")

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

func verifyToken(t string) (*verifier.Jwt, error) {

	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func getdasvid(oauthtoken string) (string) {

	defer utils.TimeTrack(time.Now(), "Get DASVID")
	
	// Asserting workload will validate oauth token, so we dont need to do it here.
	// stablish mtls with asserting workload and call mint endpoint, passing oauth token 
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	var endpoint string
	token := os.Getenv("oauthtoken")
	fmt.Println("OAuth Token: ", token)
	endpoint = "https://"+os.Getenv("ASSERTINGWLIP")+"/mint?AccessToken="+token

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	return fmt.Sprintf("%s", body)
}