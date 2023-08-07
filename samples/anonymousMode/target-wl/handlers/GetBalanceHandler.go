package handlers

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// "github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/utils"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/target-wl/models"
)


func GetBalanceHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Get_balanceHandler")

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
	if dasvidclaims.Aud != "spiffe://example.org/subject_wl"{

        returnmsg := "The application "+dasvidclaims.Iss+" is not allowed to access user data!"
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

	// Iterate over lines looking for DASVID token
	scanner := bufio.NewScanner(balance)

	for scanner.Scan() {

		json.Unmarshal([]byte(scanner.Text()), &tempbalance)
		if err != nil {
			log.Fatalf("error:", err)
		}
		
		if tempbalance.User == dasvidclaims.Dpr {
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
		User:		fmt.Sprintf("%v", dasvidclaims.Dpr),
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