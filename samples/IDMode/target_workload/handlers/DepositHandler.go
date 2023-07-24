package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/api-libs/utils"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/target-wl/models"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp
	var temp models.Contents

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// validate received token and Certs
	var rcvSVID Contents

    json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received  assertion: ", rcvSVID.DASVIDToken)
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
		returnmsg := "Error validating ECDSA assertion using received SVID!"
		log.Printf(returnmsg)
		tempbalance = models.Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

        json.NewEncoder(w).Encode(tempbalance)
        return
		
	}
	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))),
	)
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
	// Validate DASVID
	
	parts := strings.Split(rcvSVID.DASVIDToken, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[len(parts)/2 - 1])
	log.Printf(string(claims))
	var dasvidclaims DAClaims

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
	if dasvidclaims["aud"].(string) != "spiffe://example.org/subject_wl"{

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

	// Iterate over lines looking for username
	scanner := bufio.NewScanner(balance)

	for scanner.Scan() {

	json.Unmarshal([]byte(scanner.Text()), &tempbalance)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if tempbalance.User == dasvidclaims["dpr"] {

		log.Println("User " + tempbalance.User + " found! Updating balance...")

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
		User:    fmt.Sprintf("%v", dasvidclaims["dpr"]),
		Balance: 0,
	}
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode("User not found")
	}
