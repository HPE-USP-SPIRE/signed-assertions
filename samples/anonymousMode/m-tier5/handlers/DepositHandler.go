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
	// "go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/m-tier5/monitoring-prom"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/m-tier5/models"
)

var temp models.Contents

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s execution time is %s", name, elapsed)
	monitor.ExecutionTimeSummary.WithLabelValues(name).Observe(elapsed.Seconds())
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

func AssertionGen(assertionclaims map[string]interface{}, oldmain string, privateKey kyber.Scalar) (string, error) {
	defer timeTrack(time.Now(), "SchnorrAssertionGen")
	var schnorr_assertion string
	schnorr_assertion, err := dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
	if err != nil {
		log.Fatalf("Error generating signed schnorr assertion!")
	}
	return schnorr_assertion, nil
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	
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
	assertion, err = AssertionGen(assertionclaims, oldmain, privateKey)
	if err != nil {
		log.Fatalf("Error generating signed schnorr assertion!")
	}
	monitor.AssertionSize.WithLabelValues().Set(float64(len(assertion)))

	log.Printf("Generated assertion: ", fmt.Sprintf("%s",assertion))

	// Gera chamada para TARGET 5workload 
	endpoint := "https://"+os.Getenv("TARGETWLIP")+"/deposit?DASVID="+assertion+"&deposit="+r.FormValue("deposit")
	log.Printf(endpoint)
	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("TARGETWLIP"), err)
	}

	defer response.Body.Close()
	// log.Printf("%s response here####",response)
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	var tempbalance models.Balancetemp
	
	// Receive data and return it to subject.
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		fmt.Println("error:", err)
	}

	json.NewEncoder(w).Encode(tempbalance)	
}

func introspect(datoken string, client http.Client) (introspectrsp models.FileContents) {
	var rcvresp models.FileContents
	defer timeTrack(time.Now(), "introspect")
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
		log.Fatalf("Error: %v", err)
	}

	introspectrsp = models.FileContents{
		Msg:       rcvresp.Msg,
		ZKP:       rcvresp.ZKP,
		Returnmsg: "",
	}

	return introspectrsp
}
