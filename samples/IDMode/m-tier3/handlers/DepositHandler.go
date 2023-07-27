package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier3/models"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tempbalance models.Balancetemp
	
	// validate received token and Certs
	var rcvSVID models.Contents

    json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received assertion: ", rcvSVID.DASVIDToken)
	log.Print("Received SVID certs: ", rcvSVID.IDArtifacts)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID.IDArtifacts), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < len(svidcerts)-1) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(rcvSVID.DASVIDToken, ecdsakeys)
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
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

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

	updSVID := strings.Trim(strings.Join([]string{rcvSVID.IDArtifacts, idartifact}, ""), "[]")
	
	// get audience 
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial("tcp", os.Getenv("MIDDLE_TIER4_IP"), conf)
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
	assertion, err := dasvid.NewECDSAencode(assertionclaims, rcvSVID.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: %s", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: %s", fmt.Sprintf("%s",idartifact))
	log.Printf("Updated SVID bundle			: %s", fmt.Sprintf("%s",updSVID))

	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
    if err != nil {
        log.Fatal(err)
    }
	// log.Println("Generated body data: %s", json_data)

	// Gera chamada para MIDDLE_TIER4_IP workload 
	endpoint := "https://"+os.Getenv("MIDDLE_TIER4_IP")+"/deposit?DASVID="+r.FormValue("DASVID")+"&deposit="+r.FormValue("deposit")

	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLE_TIER4_IP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
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
		log.Fatalf("Error: %v", err)
	}

	introspectrsp = models.FileContents{
		Msg:       rcvresp.Msg,
		ZKP:       rcvresp.ZKP,
		Returnmsg: "",
	}

	return introspectrsp
}
