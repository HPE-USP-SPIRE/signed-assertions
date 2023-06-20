package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"context"
	"os"
	"bufio"
	"strconv"
	
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/utils"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/target-wl/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)


func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp
	var temp models.Contents
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
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
	
	datoken := r.FormValue("DASVID")
	dasvidclaims := dasvid.ParseTokenClaims(datoken)
	endpoint := "https://"+os.Getenv("ASSERTINGWLIP")+"/validate?DASVID="+datoken

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

	log.Println("Sig validation: ", *temp.DasvidSigValidation)
	log.Println("exp validation: ", *temp.DasvidExpValidation)

	var returnmsg string

	if (*temp.DasvidSigValidation == false) {
				
		returnmsg = "DA-SVID signature validation error"

		tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: returnmsg,
		}

		// log.Printf(returnmsg)
		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	if (*temp.DasvidExpValidation == false) {
				
		returnmsg = "DA-SVID expiration validation error"

		tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: returnmsg,
		}

		// log.Printf(returnmsg)
		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	// This PoC will consider that only DA-SVID with "subject_wl" in sub claim will be able request data
	if dasvidclaims["sub"].(string) != "spiffe://example.org/subject_wl"{

		returnmsg = "Unauthorized subject workload!"
		log.Printf(returnmsg)
			tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}
			json.NewEncoder(w).Encode(tempbalance)
		return
	}

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
			log.Fatalf("error:", err)
		}
		
		if tempbalance.User == dasvidclaims["dpr"] {

			log.Println("User "+tempbalance.User+" found! Updating balance...")

			log.Println("Balance is ", tempbalance.Balance)
			tmpdeposit, _ := strconv.Atoi(r.FormValue("deposit"))
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
				User:		tempbalance.User,
				Balance:	tempbalance.Balance,
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
		User:		fmt.Sprintf("%v", dasvidclaims["dpr"]),
		Balance:	0,
	}
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode("User not found")
}