package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.dedis.ch/kyber/v3/group/edwards25519"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/m-tier4/models"
)

var curve = edwards25519.NewBlakeSHA256Ed25519()

var g = curve.Point().Base()

func GetBalanceHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "DepositHandler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	issue_time 		:= time.Now().Round(0).Unix()
	oldmain 		:= r.FormValue("DASVID")
	parts 			:= strings.Split(oldmain, ".")
	var assertion string	
	
	prevsignature, err := dasvid.String2schsig(parts[len(parts) -1])
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

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Generate assertion claims
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

	endpoint := "https://"+os.Getenv("MIDDLE_TIER5_IP")+"/get_balance?DASVID="+assertion
	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLE_TIER5_IP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	var tempbalance models.Balancetemp
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		log.Fatalf("error:", err)
	}
	json.NewEncoder(w).Encode(tempbalance)	

}
