package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"net"
	"context"
	"time"
	"bufio"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	
	// dasvid lib test
	dasvid "github.com/marco-developer/dasvid/poclib"

	// To sig. validation 
	_ "crypto/sha256"
	
	"github.com/gorilla/sessions"
	// Okta
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"

	// anonymous trace
	"go.dedis.ch/kyber/v3/group/edwards25519"
	// "github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
	// Set curve
	curve = edwards25519.NewBlakeSHA256Ed25519()
	// set g
	g = curve.Point().Base()

)



type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

type PocData struct {
	AppURI			string
	Profile         map[string]string
	IsAuthenticated bool
	HaveDASVID		bool
	AccessToken     string
	PublicKey		string
	SigValidation 	string
	ExpValidation 	string
	RetClaims		map[string]interface{}
	DASVIDToken		string
	DASVIDClaims 	map[string]interface{}
	DasvidExpValidation string
	Returnmsg		string
	Balance			int
), http.StatusInternalServerError)
	}


func Get_balanceHandler(w http.ResponseWriter, r *http.Request) {
	
	defer timeTrack(time.Now(), "Get_balanceHandler")
	
	var funds Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

	// Original token
	oldmain 		:= os.Getenv("DASVIDToken")
	parts 			:= strings.Split(oldmain, ".")		

	var assertion string

	// Retrieve signature from originaltoken 
	prevsignature, err := dasvid.String2schsig(parts[1])
	if err != nil {
		log.Fatalf("Error converting string to schnorr signature!")
	} 
	privateKey := prevsignature.S
	// Discard sig.S
	parts[len(parts) -1], err = dasvid.Point2string(prevsignature.R)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	oldmain = strings.Join(parts, ".")
	publicKey := curve.Point().Mul(privateKey, g)
	// fmt.Println("Generated publicKey: ", publicKey)
		
	// Issuer
	issuer, err := dasvid.Point2string(publicKey)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	// Issuer ID
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()

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
	
	// new assertion values
	assertionclaims := map[string]interface{}{
		"iss"		:		issuer,
		"iid"		:		clientID,
		"iat"		:	 	issue_time,
	}
	assertion, err = dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
	if err != nil {
		log.Fatalf("Error generating signed schnorr assertion!")
	} 

	log.Printf("Generated assertion: ", fmt.Sprintf("%s",assertion))

	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/get_balance?DASVID="+assertion

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {
		
		fmt.Println("Return msg error:", funds.Returnmsg)
		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			HaveDASVID:				haveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		tpl.ExecuteTemplate(w, "home.gohtml", Data)	
		
	} else {

		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			Balance:				funds.Balance,
		}

		tpl.ExecuteTemplate(w, "get_balance.gohtml", Data)	
	}
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Deposit Handler")
	
	var funds Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

	// Original token
	oldmain 		:= os.Getenv("DASVIDToken")
	parts 			:= strings.Split(oldmain, ".")		

	var assertion string

	// Retrieve signature from originaltoken 
	prevsignature, err := dasvid.String2schsig(parts[1])
	if err != nil {
		log.Fatalf("Error converting string to schnorr signature!")
	} 
	privateKey := prevsignature.S
	// Discard sig.S
	parts[len(parts) -1], err = dasvid.Point2string(prevsignature.R)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	oldmain = strings.Join(parts, ".")
	publicKey := curve.Point().Mul(privateKey, g)
	// fmt.Println("Generated publicKey: ", publicKey)
		
	// Issuer
	issuer, err := dasvid.Point2string(publicKey)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	// Issuer ID
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()

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
	
	// new assertion values
	assertionclaims := map[string]interface{}{
		"iss"		:		issuer,
		"iid"		:		clientID,
		"iat"		:	 	issue_time,
	}
	assertion, err = dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
	if err != nil {
		log.Fatalf("Error generating signed schnorr assertion!")
	} 

	log.Printf("Generated assertion: ", fmt.Sprintf("%s",assertion))

	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		fmt.Println("Return msg error:", funds.Returnmsg)
		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			HaveDASVID:				haveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		tpl.ExecuteTemplate(w, "home.gohtml", Data)	
		
	} else {

		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			Balance:				funds.Balance,
		}
		
		tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	delete(session.Values, "DASVIDToken")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {

	defer timeTrack(time.Now(), "Exchange OKTA Oauth code")

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
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
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

	defer timeTrack(time.Now(), "Get DASVID")
	
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
	endpoint = "https://"+os.Getenv("ASSERTINGWLIP")+"/mintassertion?AccessToken="+token

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

func ParseEnvironment() {

	if _, err := os.Stat(".cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
	}

	setEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("PROOF_LEN", os.Getenv("PROOF_LEN"))
	if os.Getenv("PROOF_LEN") == "" {
		log.Printf("Could not resolve a PROOF_LEN environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("PEM_PATH", os.Getenv("PEM_PATH"))
	if os.Getenv("PEM_PATH") == "" {
		log.Printf("Could not resolve a PEM_PATH environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("MINT_ZKP", os.Getenv("MINT_ZKP"))
	if os.Getenv("MINT_ZKP") == "" {
		log.Printf("Could not resolve a MINT_ZKP environment variable.")
		// os.Exit(1)
	}

	// Set client APP environment
	setEnvVariable("CLIENT_ID", os.Getenv("CLIENT_ID"))
	if os.Getenv("CLIENT_ID") == "" {
		log.Printf("Could not resolve a CLIENT_ID environment variable.")
		os.Exit(1)
	}

	setEnvVariable("CLIENT_SECRET", os.Getenv("CLIENT_SECRET"))
	if os.Getenv("CLIENT_SECRET") == "" {
		log.Printf("Could not resolve a CLIENT_SECRET environment variable.")
		os.Exit(1)
	}

	setEnvVariable("ISSUER", os.Getenv("ISSUER"))
	if os.Getenv("ISSUER") == "" {
		log.Printf("Could not resolve a ISSUER environment variable.")
		os.Exit(1)
	}

	setEnvVariable("HOSTIP", os.Getenv("HOSTIP"))
	if os.Getenv("HOSTIP") == "" {
		log.Printf("Could not resolve a HOSTIP environment variable.")
		os.Exit(1)
	}

	setEnvVariable("ASSERTINGWLIP", os.Getenv("ASSERTINGWLIP"))
	if os.Getenv("ASSERTINGWLIP") == "" {
		log.Printf("Could not resolve a ASSERTINGWLIP environment variable.")
		os.Exit(1)
	}

	setEnvVariable("TARGETWLIP", os.Getenv("TARGETWLIP"))
	if os.Getenv("TARGETWLIP") == "" {
		log.Printf("Could not resolve a TARGETWLIP environment variable.")
		os.Exit(1)
	}

	setEnvVariable("MIDDLETIERIP", os.Getenv("MIDDLETIERIP"))
	if os.Getenv("MIDDLETIERIP") == "" {
		log.Printf("Could not resolve a MIDDLETIERIP environment variable.")
		os.Exit(1)
	}

	setEnvVariable("TRUST_DOMAIN", os.Getenv("TRUST_DOMAIN"))
	if os.Getenv("TRUST_DOMAIN") == "" {
		log.Printf("Could not resolve a TRUST_DOMAIN environment variable.")
		// os.Exit(1)
	}
}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".cfg")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
}