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
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	
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
	"crypto/x509"
	"encoding/pem"
	"crypto/ecdsa"
	"crypto/tls"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
	// Set curve
	curve = edwards25519.NewBlakeSHA256Ed25519()

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
	IDArtifacts		string `json:",omitempty"`
}

type Contents struct {
	OauthSigValidation 			*bool `json:",omitempty"`
	OauthExpValidation 			*bool `json:",omitempty"`
	OauthExpRemainingTime		string `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
	IDArtifacts					string `json:",omitempty"`
}

type Balancetemp struct {
	User						string `json:",omitempty"`
	Balance						int `json:",omitempty"`
	Returnmsg					string `json:",omitempty"`

}

var temp Contents
var oktaclaims map[string]interface{}
var dasvidclaims map[string]interface{}
var Data PocData

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GetOutboundIP(port string) string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
    return uri
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func main() {

	// sessionStore.Options.MaxAge = 180
	ParseEnvironment()

	// Retrieve local IP
	uri := GetOutboundIP(":8080")

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/callback", AuthCodeCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)

	http.HandleFunc("/account", AccountHandler)
	http.HandleFunc("/get_balance", Get_balanceHandler)
	http.HandleFunc("/deposit", DepositHandler)

	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	log.Print("Subject workload starting at ", uri)
	err := http.ListenAndServe(uri, nil)
	if err != nil {
		log.Printf("the Subject workload HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	
	Data = PocData{
		AppURI:			 os.Getenv("HOSTIP"),
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
		AccessToken:	 strAT,
	}

	
	tpl.ExecuteTemplate(w, "home.gohtml", Data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Login")

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
	defer timeTrack(time.Now(), "Callback Handler")

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

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
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

	defer timeTrack(time.Now(), "Profile Handler")

	Data = PocData{
		AppURI:			 os.Getenv("HOSTIP"),
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", Data)
}

func AccountHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Account Handler")

	log.Print("Contacting Assertingwl to retrieve assertion... ")

	receivedAssertion := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedAssertion), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received assertion: ", receivedAssertion)

	if (*temp.OauthSigValidation == false) || (*temp.OauthExpValidation == false) {

		returnmsg := "Oauth token validation error"

		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			Returnmsg: 				returnmsg,
		}

		log.Printf(returnmsg)
		tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		os.Setenv("DASVIDToken", temp.DASVIDToken)
		os.Setenv("IDArtifacts", temp.IDArtifacts)

		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDToken:			temp.DASVIDToken,
			// DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			SigValidation: 			fmt.Sprintf("%v", temp.OauthSigValidation),
			ExpValidation:			fmt.Sprintf("%v", temp.OauthExpValidation),
		}

		tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}

func Get_balanceHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Get_balanceHandler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds Balancetemp
	
	// validate received token and Certs
	receivedAssertion := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedAssertion), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received assertion: ", temp.DASVIDToken)

	rcvSVID := temp.IDArtifacts
	log.Print("Received SVID cert: ", rcvSVID)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < (len(svidcerts)-1)) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(temp.DASVIDToken, ecdsakeys)
	if valid == false {
		log.Fatalf("Error validating ECDSA assertion using SVID!")
		
	}

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

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

	// Generate a new ecdsa signed assertion containing key:value with no specific audience
	// Fetch claims data
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()
	clientkey 		:= clientSVID.PrivateKey

	// generate idartifact
	// Uses SVID cert bundle as ISSUER
	tmp, _, err := clientSVID.Marshal()
	if err != nil {
		log.Fatal("Error retrieving SVID: ", err)
	}
	svidcert := strings.SplitAfter(fmt.Sprintf("%s", tmp), "-----END CERTIFICATE-----")

	idartifact := svidcert[0]

	updSVID := strings.Trim(strings.Join([]string{rcvSVID, fmt.Sprintf("%s", idartifact)}, ""), "[]")
	log.Println("Updated SVID bundle: %s", updSVID)
	
	// get audience 
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial("tcp", os.Getenv("MIDDLETIERIP"), conf)
    if err != nil {
        log.Println("Error in Dial", err)
        return
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
	audienceid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Audience SPIFFE-ID: %v", audienceid)

	// Generate assertion claims
	assertionclaims := map[string]interface{}{
		"iss"		:		clientID,
		"aud"		:		audienceid,
		"iat"		:	 	issue_time,
	}
	assertion, err := dasvid.NewECDSAencode(assertionclaims, temp.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: ", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: ", fmt.Sprintf("%s",idartifact))

	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
    if err != nil {
        log.Fatal(err)
    }
	// log.Println("Generated body data: %s", fmt.Sprintf("%s",json_data))

	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/get_balance?DASVID="+assertion
	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		log.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		log.Println("Return msg error:", funds.Returnmsg)
		Data = PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			HaveDASVID:				haveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		tpl.ExecuteTemplate(w, "home.gohtml", Data)	
		
	} else {

		log.Println("Received balance: %d", funds.Balance)

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds Balancetemp
	
	// validate received token and Certs
	receivedAssertion := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedAssertion), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received assertion: ", temp.DASVIDToken)

	rcvSVID := temp.IDArtifacts
	log.Print("Received SVID cert: ", rcvSVID)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < (len(svidcerts)-1)) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(temp.DASVIDToken, ecdsakeys)
	if valid == false {
		log.Fatalf("Error validating ECDSA assertion using SVID!")
		
	}

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

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

	// Generate a new ecdsa signed assertion containing key:value with no specific audience
	// Fetch claims data
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()
	clientkey 		:= clientSVID.PrivateKey

	// generate idartifact
	// Uses SVID cert bundle as ISSUER
	tmp, _, err := clientSVID.Marshal()
	if err != nil {
		log.Fatal("Error retrieving SVID: ", err)
	}
	svidcert := strings.SplitAfter(fmt.Sprintf("%s", tmp), "-----END CERTIFICATE-----")

	idartifact := svidcert[0]

	updSVID := strings.Trim(strings.Join([]string{rcvSVID, fmt.Sprintf("%s", idartifact)}, ""), "[]")
	log.Println("Updated SVID bundle: %s", updSVID)
	
	// get audience 
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial("tcp", os.Getenv("MIDDLETIERIP"), conf)
    if err != nil {
        log.Println("Error in Dial", err)
        return
    }
    defer conn.Close()
    certs := conn.ConnectionState().PeerCertificates
	audienceid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Audience SPIFFE-ID: %v", audienceid)

	// Generate assertion claims
	assertionclaims := map[string]interface{}{
		"iss"		:		clientID,
		"aud"		:		audienceid,
		"iat"		:	 	issue_time,
	}
	assertion, err := dasvid.NewECDSAencode(assertionclaims, temp.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: ", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: ", fmt.Sprintf("%s",idartifact))

	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
    if err != nil {
        log.Fatal(err)
    }

	// With dasvid, app can make a call to middle tier, asking for user funds.
	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")
	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLE_TIER2_IP"), err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

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
	endpoint = "https://"+os.Getenv("ASSERTINGWLIP")+"/ecdsaassertion?AccessToken="+token

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