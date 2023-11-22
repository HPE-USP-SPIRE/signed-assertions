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

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Deposit Handler")

	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	////////// DECODE LSVID ////////////
	json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received LSVID: ", rcvSVID.DASVIDToken)

	decCallerLSVID, err := lsvid.Decode(rcvSVID.DASVIDToken)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v\n", err)
	}
	
	////////// VALIDATE LSVID ////////////
	checkLSVID, err := lsvid.Validate(decCallerLSVID.Token)
	if err != nil {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}
	if checkLSVID == false {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}

	// Now, verify if bearer == aud
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}

	//TODO: corrigir e descomentar. Erro: cannot convert clientspiffeid (variable of type spiffeid.ID) to type string. se tentar sem o string(), da erro de comparação de tipos diferentes.
	// if (string(clientspiffeid) != decCallerLSVID.Token.Payload.Aud.CN) {
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

	extendedPayload := &lsvid.Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&lsvid.IDClaim{
			CN:	subjectID,
			ID:	decSubject.Token,
		},
		Aud:	&lsvid.IDClaim{
			CN:	clientspiffeid.String(),
		},
	}

	extendedLSVID, err := lsvid.Extend(decCallerLSVID, extendedPayload, subjectKey)
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
