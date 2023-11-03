package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/global"
	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/models"
	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
)

func BalanceHandler(w http.ResponseWriter, r *http.Request) {

	defer utils.TimeTrack(time.Now(), "Get_balanceHandler")

	var (
		tempbalance models.Balancetemp
		temp        models.Contents
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(global.Options.SocketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString(global.Options.TrustDomain)

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Validate DASVID
	datoken := r.FormValue("DASVID")
	endpoint := "https://" + global.Options.AssertingWLIP + "/validate?DASVID=" + datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", global.Options.AssertingWLIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	var returnmsg string

	log.Println("Sig validation: ", *temp.DasvidSigValidation)
	log.Println("exp validation: ", *temp.DasvidExpValidation)

	if *temp.DasvidSigValidation == false {

		returnmsg = "DA-SVID signature validation error"

		tempbalance = models.Balancetemp{
			User:      "",
			Balance:   0,
			Returnmsg: returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	if *temp.DasvidExpValidation == false {

		returnmsg = "DA-SVID expiration validation error"
		log.Println("Return Msg: ", tempbalance.Returnmsg)

		tempbalance = models.Balancetemp{
			User:      "",
			Balance:   0,
			Returnmsg: returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	// Contact Asserting Workload /introspect and retrieve a ZKP proving OAuth token signature
	var introspectrsp models.FileContents
	introspectrsp = introspect(r.FormValue("DASVID"), *client)
	if introspectrsp.Returnmsg != "" {
		log.Println("ZKP error! %v", introspectrsp.Returnmsg)
		json.NewEncoder(w).Encode(introspectrsp)
	}

	// Create OpenSSL vkey using DASVID
	log.Println("introspectrsp.PubKey: %s", string(introspectrsp.PubKey))
	var pubkey dasvid.JWK
	err = json.Unmarshal(introspectrsp.PubKey, &pubkey)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
	}
	tmpvkey := dasvid.Pubkey2evp(pubkey)

	// Verify /introspect response correctness.
	hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
	if hexresult == false {
		log.Fatal("Error verifying hexproof!!")
	}
	log.Println("Success verifying hexproof in middle-tier!!")

	// Access Target WL and request DASVID user balance
	endpoint = "https://" + global.Options.MiddleTierIP + "/get_balance?DASVID=" + r.FormValue("DASVID")

	response, err = client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", global.Options.MiddleTierIP, err)
	}

	defer response.Body.Close()
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		fmt.Println("error:", err)
	}

	json.NewEncoder(w).Encode(tempbalance)

}

func introspect(datoken string, client http.Client) (introspectrsp models.FileContents) {

	// Introspect DA-SVID
	// var returnmsg string
	var rcvresp models.FileContents

	endpoint := "https://" + global.Options.AssertingWLIP + "/introspect?DASVID=" + datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", global.Options.AssertingWLIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &rcvresp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	introspectrsp = models.FileContents{
		Msg:       rcvresp.Msg,
		ZKP:       rcvresp.ZKP,
		PubKey:    rcvresp.PubKey,
		Returnmsg: "",
	}
	return introspectrsp
}
