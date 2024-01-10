package handlers

import (

	// "crypto/rand"
	// "encoding/base64"
	// "encoding/hex"

	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"

	// "html/template"
	"io/ioutil"
	"log"
	"net/http"

	// "net"

	"time"

	// "bufio"

	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Deposit Handler")
 
	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	////////// DECODE LSVID /////////////
	// Get LSVID from asserting
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

	// TODO Now, verify if sender == issuer
	// certs := r.TLS.PeerCertificates
	// clientspiffeid, err := x509svid.IDFromCert(certs[0])
	// if err != nil {
	// 	log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	// }

	// if (clientspiffeid.String() != decReceivedLSVID.Token.Payload.Iss.CN) {
	//  log.Fatalf("Bearer does not match issuer value: %v\n", err)
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

	log.Printf("Final extended LSVID: ", fmt.Sprintf("%s",extendedLSVID))
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

	// Make call to middle tier, asking for user funds.
	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")
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
		fmt.Println("error:", err)
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

		local.Tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}
