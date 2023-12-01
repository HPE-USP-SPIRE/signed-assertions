package handlers

import (
	"bytes"
	// "crypto/rand"
	// "encoding/base64"
	// "encoding/hex"
	"encoding/json"
	"fmt"

	// "html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	// "net"
	"context"
	"time"

	// "bufio"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/models"

	// To sig. validation
	_ "crypto/sha256"
	"crypto/tls"
	// "github.com/gorilla/sessions"
	// Okta
	// verifier "github.com/okta/okta-jwt-verifier-golang"
	// oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
	// anonymous trace
	// "go.dedis.ch/kyber/v3/group/edwards25519"
	// "github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// var oktaclaims map[string]interface{}
// var dasvidclaims map[string]interface{}

func BalanceHandler(w http.ResponseWriter, r *http.Request) {

	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	////////// DECODE LSVID ////////////
	// Get LSVID
	receivedLSVID := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedLSVID), &rcvSVID)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received LSVID: ", rcvSVID.DASVIDToken)

	// Decode LSVID from b64
	decReceivedLSVID, err := lsvid.Decode(rcvSVID.DASVIDToken)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v\n", err)
	}
	log.Print("Decoded LSVID: ", decReceivedLSVID)
	
	////////// VALIDATE LSVID ////////////
	checkLSVID, err := lsvid.Validate(decReceivedLSVID.Token)
	if err != nil {
		log.Fatalf("Error validating LSVID : %v\n", err)
	}
	if checkLSVID == false {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}

	// Now, verify if sender == issuer
	// certs := r.TLS.PeerCertificates
	// clientspiffeid, err := x509svid.IDFromCert(certs[0])
	// if err != nil {
	// 	log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	// }
	// if (clientspiffeid.String() != decReceivedLSVID.Token.Payload.Iss.CN) {
	//  log.Fatalf("Bearer does not match audience value: %v\n", err)
	// }

	////////// EXTEND LSVID ////////////
	// Fetch subject workload data
	subjectSVID	:= dasvid.FetchX509SVID()
	subjectID := subjectSVID.ID.String()
	subjectKey := subjectSVID.PrivateKey

	// Fetch subject workload LSVID
	subjectLSVID, err := lsvid.FetchLSVID(ctx, local.Options.SocketPath)
	if err != nil {
		log.Fatalf("Error fetching LSVID: %v\n", err)
	}

	// decode subject wl  LSVID
	decSubject, err := lsvid.Decode(subjectLSVID)
	if err != nil {
		log.Fatalf("Unable to decode LSVID %v\n", err)
	}

	// Get MT's SPIFFE ID
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", os.Getenv("MIDDLETIERIP"), conf)
	if err != nil {
		log.Println("Error in Dial", err)
		return
	}
	defer conn.Close()
	mtierCerts := conn.ConnectionState().PeerCertificates
	mtClientId, err := x509svid.IDFromCert(mtierCerts[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}

	extendedPayload := &lsvid.Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&lsvid.IDClaim{
			CN:	subjectID,
			ID:	decSubject.Token,
		},
		Aud:	&lsvid.IDClaim{
			CN:	mtClientId.String(),
		},
	}

	extendedLSVID, err := lsvid.Extend(decReceivedLSVID, extendedPayload, subjectKey)
	if err != nil {
		log.Fatal("Error extending LSVID: %v\n", err)
	} 

	log.Printf("Extended LSVID: ", fmt.Sprintf("%s",extendedLSVID))

	//////////////////////
	// Prepare to send extended lsvid
	values := map[string]string{"DASVIDToken": extendedLSVID}
	json_data, err := json.Marshal(values)
	if err != nil {
		log.Fatal(err)
	}

	// Connection setup
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

	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/get_balance?DASVID="+os.Getenv("DASVIDToken")
	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		log.Println("error:", err)
	}

	if tempbalance.Returnmsg != "" {

		fmt.Println("Return msg error:", tempbalance.Returnmsg)
		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			HaveDASVID:      haveDASVID(),
			Returnmsg:       tempbalance.Returnmsg,
		}

		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			DASVIDClaims:    dasvidclaims,
			HaveDASVID:      haveDASVID(),
			Balance:         tempbalance.Balance,
		}

		local.Tpl.ExecuteTemplate(w, "get_balance.gohtml", Data)
	}
}


// func getdasvid(oauthtoken string) (string) {

// 	defer timeTrack(time.Now(), "Get DASVID")
	
// 	// Asserting workload will validate oauth token, so we dont need to do it here.
// 	// stablish mtls with asserting workload and call mint endpoint, passing oauth token 
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
// 	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
// 	if err != nil {
// 		log.Fatalf("Unable to create X509Source %v", err)
// 	}
// 	defer source.Close()

// 	// Allowed SPIFFE ID
// 	serverID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))

// 	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
// 	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
// 	client := &http.Client{
// 		Transport: &http.Transport{
// 			TLSClientConfig: tlsConfig,
// 		},
// 	}

// 	var endpoint string
// 	token := os.Getenv("oauthtoken")
// 	fmt.Println("OAuth Token: ", token)
// 	endpoint = "https://"+os.Getenv("ASSERTINGWLIP")+"/ecdsaassertion?AccessToken="+token

// 	r, err := client.Get(endpoint)
// 	if err != nil {
// 		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
// 	}

// 	defer r.Body.Close()
// 	body, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		log.Fatalf("Unable to read body: %v", err)
// 	}

// 	return fmt.Sprintf("%s", body)
// }

// func isAuthenticated(r *http.Request) bool {
// 	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
// 	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
// 		return false
// 	}
// return true
// }

// func haveDASVID() bool {
// 	if os.Getenv("DASVIDToken") == "" {
// 		return false
// 	}
// return true
// }

// func getProfileData(r *http.Request) map[string]string {


// 	m := make(map[string]string)

// 	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

// 	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
// 		return m
// 	}

// 	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

// 	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
// 	h := req.Header
// 	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
// 	h.Add("Accept", "application/json")

// 	client := &http.Client{}
// 	resp, _ := client.Do(req)
// 	body, _ := ioutil.ReadAll(resp.Body)
// 	defer resp.Body.Close()
// 	json.Unmarshal(body, &m)

// 	return m
// }

// func generateState() string {
// 	// Generate a random byte array for state paramter
// 	b := make([]byte, 16)
// 	rand.Read(b)
// 	return hex.EncodeToString(b)
// }