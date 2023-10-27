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
	"strings"
	"crypto/x509"
	"encoding/pem"
	"crypto/ecdsa"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/models"

	// To sig. validation 
	_ "crypto/sha256"

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

	defer timeTrack(time.Now(), "Get Balance")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds models.Balancetemp
	var temp models.Contents

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

		fmt.Println("Return msg error:", funds.Returnmsg)
		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			HaveDASVID:      haveDASVID(),
			Returnmsg:       funds.Returnmsg,
		}

		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			DASVIDClaims:    dasvidclaims,
			HaveDASVID:      haveDASVID(),
			Balance:         funds.Balance,
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