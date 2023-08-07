package handlers

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/utils"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/target-wl/models"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	
)














func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp
	var dasvidclaims models.DAClaims

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
	log.Println("Received token: ", datoken)
	// Use galindo-garcia to validate token
	if (dasvid.Validategg(datoken) == false) {
		returnmsg := "Galindo-Garcia validation failed!"
		log.Printf(returnmsg)
		tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

        json.NewEncoder(w).Encode(tempbalance)
        return
	}
	// Validate DASVID
	parts := strings.Split(datoken, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[len(parts)/2 - 1])
	log.Printf(string(claims))

	json.Unmarshal(claims, &dasvidclaims)
	if err != nil {
		log.Fatalf("error:", err)
	}
	// ZKP validation of original dasvid
	// Contact Asserting Workload /introspect and retrieve a ZKP proving OAuth token signature
	// var introspectrsp FileContents
	tmp := []string{parts[len(parts)/2 - 1], parts[len(parts)/2]}
	original := strings.Join(tmp[0:2], ".")
	log.Printf(original)
	introspectrsp := introspect(original, *client)
	if introspectrsp.Returnmsg != "" {
		log.Println("ZKP error! %v", introspectrsp.Returnmsg)
		json.NewEncoder(w).Encode(introspectrsp)
	}

	// Create OpenSSL vkey using DASVID
	tmpvkey := dasvid.Assertion2vkey(original, 1)

	// Verify /introspect response correctness.
	hexresult := dasvid.VerifyHexProof(introspectrsp.ZKP, introspectrsp.Msg, tmpvkey)
	if hexresult == false {
		log.Fatal("Error verifying hexproof!!")
	}
	log.Println("Success verifying hexproof!!")

	// This PoC will consider that only DA-SVID with "subject_wl" in sub claim will be able request data
	if dasvidclaims.Aud != "spiffe://example.org/subject_wl" {

		returnmsg := "The application " + dasvidclaims.Iss + " is not allowed to access user data!"
		log.Printf(returnmsg)

		tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg:	returnmsg,
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
			log.Fatalf("error: %v", err)
		}

		if tempbalance.User == dasvidclaims.Dpr {

			log.Println("User " + tempbalance.User + " found! Updating balance...")

			log.Println("Balance is ", tempbalance.Balance)
			tmpdeposit, err := strconv.Atoi(r.FormValue("deposit"))
			log.Printf(fmt.Sprintf("%s",tmpdeposit))
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
		User:		fmt.Sprintf("%v", dasvidclaims.Dpr),
		Balance:	0,
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
		Msg:		rcvresp.Msg,
		ZKP:		rcvresp.ZKP,
		Returnmsg:	"",
	}
return introspectrsp
}
