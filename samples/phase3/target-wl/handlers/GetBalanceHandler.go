package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"

	"log"

	"net/http"
	"os"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	// TODO voltar junto com aud=iss "github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/hpe-usp-spire/signed-assertions/phase3/target-wl/monitoring-prom"
	"github.com/hpe-usp-spire/signed-assertions/phase3/target-wl/models"

	// LSVID pkg
	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
)

func GetBalanceHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "GetBalanceHandler")

	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received LSVID: ", rcvSVID.DASVIDToken)
	monitor.AssertionSize.WithLabelValues().Set(float64(len(rcvSVID.DASVIDToken)))
	monitor.SVIDCertSize.WithLabelValues().Set(float64(len(rcvSVID.IDArtifacts)))
	
	decLSVID, err := lsvid.Decode(rcvSVID.DASVIDToken)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v\n", err)
	}

	checkLSVID, err := lsvid.Validate(decLSVID.Token)
	if err != nil {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}
	if checkLSVID == false {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}

	//TODO: corrigir e descomentar.

	// Now, verify if bearer == aud
	// certs := r.TLS.PeerCertificates
	// clientspiffeid, err := x509svid.IDFromCert(certs[0])
	// if err != nil {
	// 	log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	// }

	// if (clientspiffeid.String() != decLSVID.Token.Payload.Aud.CN) {
	//   log.Fatalf("Bearer does not match audience value: %v\n", err)
	// }
	
	//TODO - declaração de ctx?
	//TODO - create X509 source blablabla
	//TODO - TLS CONFIG? 
	//TODO - serverID?
	
	// If reaches this point, all validations was successful, so we can proceed to access user data and return it.
	// Open dasvid cache file
	balance, err := os.OpenFile("./data/balance.data", os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer balance.Close()

	// TODO: Iterate over nested lsvids looking for Dpr Claim. Right now, it is hardcoded for this scenario 

	Dpr := decLSVID.Token.Nested.Nested.Payload.Dpr
	log.Printf("Dpr Claim: %v", Dpr)

	// Iterate over lines looking for DASVID token
	scanner := bufio.NewScanner(balance)

	for scanner.Scan() {

		json.Unmarshal([]byte(scanner.Text()), &tempbalance)
		if err != nil {
			log.Fatalf("error:", err)
		}
		
		if tempbalance.User == Dpr {
			log.Printf("User %s found!", tempbalance.User)
			json.NewEncoder(w).Encode(tempbalance)
			return
		}
    }
    if scanner.Err() != nil {
        log.Printf("Error reading Balance data file: %v", scanner.Err())
    }

	f, err := os.OpenFile("./data/balance.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Adding user to file...\n")

	tempbalance = models.Balancetemp{
		User:		fmt.Sprintf("%v", Dpr),
		Balance:	0,
		Returnmsg:	"",
	}
	log.Printf("tempbalance = %v\n", tempbalance)
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}

	json.NewEncoder(w).Encode("User not found")
}

// func introspect(datoken string, client http.Client) (introspectrsp models.FileContents) {
// 	var rcvresp models.FileContents

// 	endpoint := "https://" + os.Getenv("ASSERTINGWLIP") + "/introspect?DASVID=" + datoken

// 	response, err := client.Get(endpoint)
// 	if err != nil {
// 		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
// 	}

// 	defer response.Body.Close()
// 	body, err := ioutil.ReadAll(response.Body)
// 	if err != nil {
// 		log.Fatalf("Unable to read body: %v", err)
// 	}

// 	err = json.Unmarshal([]byte(body), &rcvresp)
// 	if err != nil {
// 		log.Fatalf("Error: %v", err)
// 	}

// 	introspectrsp = models.FileContents{
// 		Msg:       rcvresp.Msg,
// 		ZKP:       rcvresp.ZKP,
// 		Returnmsg: "",
// 	}

// 	return introspectrsp
// }