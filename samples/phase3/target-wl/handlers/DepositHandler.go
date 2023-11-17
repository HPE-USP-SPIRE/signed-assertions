package handlers

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"io/ioutil"
	"log"

	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/hpe-usp-spire/signed-assertions/phase3/target-wl/models"

	// LSVID pkg
	lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received LSVID: ", rcvSVID.DASVIDToken)

	decLSVID, err := lsvid.Decode(rcvSVID.DASVIDToken)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v\n", err)
	}

	checkLSVID, err := lsvid.Validate(decLSVID.Token)
	if err != nil {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}
	if checkLSVID == false {
		log.Printf("LSVID validation failed!")
		tempbalance = models.Balancetemp{
			User:      "",
			Balance:   0,
			Returnmsg: "LSVID validation failed!",
		}
	
		return json.NewEncoder(w).Encode(tempbalance)
	}

	// Now, verify if bearer == aud
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	if (clientspiffeid != decLSVID.Token.Aud.CN) {
		log.Printf("Bearer does not match audience value!")
		tempbalance = models.Balancetemp{
			User:      "",
			Balance:   0,
			Returnmsg: "Bearer does not match audience value!",
		}
	
		return json.NewEncoder(w).Encode(tempbalance)
	}

	// // PS: Skip ZKP validation in the first step of PHASE 3 development.
	// // ZKP validation of original dasvid
	// // Contact Asserting Workload /introspect and retrieve a ZKP proving OAuth token signature
	// // var introspectrsp FileContents
	// tmp := []string{parts[len(parts)/2-1], parts[len(parts)/2]}
	// original := strings.Join(tmp[0:2], ".")
	// log.Printf(original)
	// introspectrsp := introspect(original, *client)
	// if introspectrsp.Returnmsg != "" {
	// 	log.Println("ZKP error! %v", introspectrsp.Returnmsg)
	// 	json.NewEncoder(w).Encode(introspectrsp)
	// }

	// // Create OpenSSL vkey using DASVID
	// tmpvkey := dasvid.Assertion2vkey(original, 1)

	// // Verify /introspect response correctness.
	// hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
	// if hexresult == false {
	// 	log.Fatal("Error verifying hexproof!!")
	// }
	// log.Println("Success verifying hexproof!!")

	// If reaches this point, all validations was successful, so we can proceed to access user data and return it.
	// Open dasvid cache file
	balance, err := os.OpenFile("./data/balance.data", os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer balance.Close()

	// Iterate over lines looking for username
	scanner := bufio.NewScanner(balance)

	for scanner.Scan() {

		json.Unmarshal([]byte(scanner.Text()), &tempbalance)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		if tempbalance.User == dasvidclaims.Dpr {

			log.Println("User " + tempbalance.User + " found! Updating balance...")

			log.Println("Balance is ", tempbalance.Balance)
			tmpdeposit, err := strconv.Atoi(r.FormValue("deposit"))
			if err != nil {
				log.Fatalf("error: %v", err)
			}
			tempbalance.Balance += tmpdeposit
			log.Println("New Balance is ", tempbalance.Balance)
			tmp, err := json.Marshal(tempbalance)
			if err != nil {
				fmt.Println("error:", err)
			}

			err = os.WriteFile("./data/balance.data", []byte(tmp), 0)
			if err != nil {
				panic(err)
			}

			tempbalance = models.Balancetemp{
				User:    tempbalance.User,
				Balance: tempbalance.Balance,
			}

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
	log.Printf("Adding user to file...")

	tempbalance = models.Balancetemp{
		User:    fmt.Sprintf("%v", dasvidclaims.Dpr),
		Balance: 0,
	}
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode("User not found")
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
