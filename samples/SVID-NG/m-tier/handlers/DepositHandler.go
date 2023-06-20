package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/m-tier/models"
)

var temp models.Contents

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s execution time is %s", name, elapsed)

	// If the file doesn't exist, create it, or append to the file
	file, err := os.OpenFile("./bench.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Writing to file...")
	json.NewEncoder(file).Encode(fmt.Sprintf("%s execution time is %s", name, elapsed))
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))),
	)
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a 'tls.Config' to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// validate DASVID
	endpoint := "https://" + os.Getenv(
		"ASSERTINGWLIP",
	) + "/validate?DASVID=" + r.FormValue(
		"DASVID",
	)

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
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
	log.Println("Exp validation: ", *temp.DasvidExpValidation)

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
		log.Println("Return message: ", tempbalance.Returnmsg)

		tempbalance = models.Balancetemp{
			User:      "",
			Balance:   0,
			Returnmsg: returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	// Contact Asserting Workload /introspect and retrieve ZKP proving OAuth token signature
	var introspectrsp models.FileContents
	introspectrsp = introspect(r.FormValue("DASVID"), *client)
	if introspectrsp.Returnmsg != "" {
		log.Println("ZKP error! %v", introspectrsp.Returnmsg)
		json.NewEncoder(w).Encode(introspectrsp)
	}

	// Create OpenSSL key using DASVID
	log.Println("introspectrsp.PubKey: %s", string(introspectrsp.PubKey))
	var pubkey dasvid.JWK

	err = json.Unmarshal(introspectrsp.PubKey, &pubkey)
	if err != nil {
		fmt.Println("Error parsing JSON: ", err)
	}

	tmpvkey, err := dasvid.Pubkey2evp(pubkey)
	if err != nil {
		fmt.Println("Error creating vkey:", err)
	}

	// Verify /introspect response correctness.
	hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
	if hexresult == false {
		log.Fatal("Error verifying hexproof!!")
	}

	log.Println("Success verifying hexproof in middle-tier!!")

	// Access Target WL and request DASVID user Balance
	endpoint = "https://" + os.Getenv(
		"TARGETWLIP",
	) + "/get_balance?DASVID=" + r.FormValue(
		"DASVID",
	)

	response, err = client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
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
	var rcvresp models.FileContents

	endpoint := "https://" + os.Getenv("ASSERTINGWLIP") + "/introspect?DASVID=" + datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &rcvresp)
	if err != nil {
		log.Fatalf("Error: ", err)
	}

	introspectrsp = models.FileContents{
		Msg:       rcvresp.Msg,
		ZKP:       rcvresp.ZKP,
		PubKey:    rcvresp.PubKey,
		Returnmsg: "",
	}

	return introspectrsp
}
