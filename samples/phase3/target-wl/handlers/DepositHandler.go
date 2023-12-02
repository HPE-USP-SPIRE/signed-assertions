package handlers

import (
	"bufio"
	"encoding/json"

	"log"

	"net/http"
	"os"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/utils"

	"github.com/hpe-usp-spire/signed-assertions/phase3/target-wl/models"
	// LSVID pkg
	// lsvid "github.com/hpe-usp-spire/signed-assertions/lsvid"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "DepositHandler")

	var tempbalance models.Balancetemp
	var rcvSVID models.Contents

	json.NewDecoder(r.Body).Decode(&rcvSVID)
	log.Print("Received LSVID: ", rcvSVID.DASVIDToken)

	decLSVID, err := lsvid.Decode(rcvSVID.DASVIDToken)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v\n", err)
	}
	log.Print("FORMATO DO DECLSVID:", decLSVID)

	checkLSVID, err := lsvid.Validate(decLSVID.Token)
	if err != nil {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}
	if checkLSVID == false {
		log.Fatalf("Error validating LSVID: %v\n", err)
	}

	// Now, verify if bearer == aud
	certs := r.TLS.PeerCertificates
	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	//TODO: corrigir e descomentar. Erro: cannot convert clientspiffeid (variable of type spiffeid.ID) to type string. se tentar sem o string(), da erro de comparação de tipos diferentes.
	if (clientspiffeid.String() != decLSVID.Token.Payload.Aud.CN) {
	  log.Fatalf("Bearer does not match audience value: %v\n", err)
	}
	
	//TODO - declaração de ctx?
	//TODO - create X509 source blablabla
	//TODO - TLS CONFIG? 
	//TODO - serverID?

	// checkLSVID, err := lsvid.Validate(decLSVID.Token)
	// if err != nil {
	// 	log.Fatalf("Error validating LSVID: %v\n", err)
	// }
	// if checkLSVID == false {
	// 	log.Fatalf("Error validating LSVID: %v\n", err)
	// }

	
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

		if tempbalance.User == clientspiffeid.String() { //TODO qual propriedade do LSVID deveria estar aqui? 

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

	// f, err := os.OpenFile("./data/balance.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("Adding user to file...")

	tempbalance = models.Balancetemp{
		User:    fmt.Sprintf("%v", clientspiffeid.String()),
		Balance: 0,
	}
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