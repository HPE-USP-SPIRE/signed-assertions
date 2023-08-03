package main

import (
	
	"encoding/json"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"context"
	"io/ioutil"
	"time"
	"bufio"
	"net"
	"strconv"
	"strings"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	
	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"

)

var Data PocData
var Filetemp FileContents
var temp Contents


func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}



func Get_balanceHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Get_balanceHandler")

	var tempbalance Balancetemp

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
		tempbalance = Balancetemp{
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
	log.Println("Success verifying hexproof in middle-tier!!")

    // This PoC will consider that only DA-SVID with "subject_wl" in sub claim will be able request data
	if dasvidclaims.Aud != "spiffe://example.org/subject_wl"{

        returnmsg := "The application "+dasvidclaims.Iss+" is not allowed to access user data!"
		log.Printf(returnmsg)

		tempbalance = Balancetemp{
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

	tempbalance = Balancetemp{
		User:		fmt.Sprintf("%v", dasvidclaims.Dpr),
		Balance:	0,
	}
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}

	json.NewEncoder(w).Encode("User not found")
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "DepositHandler")

	var tempbalance Balancetemp

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
		tempbalance = Balancetemp{
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
	log.Println("Success verifying hexproof in middle-tier!!")

    // This PoC will consider that only DA-SVID with "subject_wl" in sub claim will be able request data
	if dasvidclaims.Aud != "spiffe://example.org/subject_wl"{

        returnmsg := "The application "+dasvidclaims.Iss+" is not allowed to access user data!"
		log.Printf(returnmsg)

		tempbalance = Balancetemp{
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
		
		if tempbalance.User == dasvidclaims.Dpr {

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

			tempbalance = Balancetemp{
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

	tempbalance = Balancetemp{
		User:		fmt.Sprintf("%v", dasvidclaims.Dpr),
		Balance:	0,
	}
	json.NewEncoder(f).Encode(tempbalance)
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode("User not found")
}

func GetOutboundIP(port string) string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
    return uri
}


func ParseEnvironment() {

	if _, err := os.Stat(".cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
	}

	setEnvVariable("PROOF_LEN", os.Getenv("PROOF_LEN"))
	if os.Getenv("PROOF_LEN") == "" {
		log.Printf("Could not resolve a PROOF_LEN environment variable.")
		// os.Exit(1)
	}
	
	setEnvVariable("PEM_PATH", os.Getenv("PEM_PATH"))
	if os.Getenv("PEM_PATH") == "" {
		log.Printf("Could not resolve a PEM_PATH environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("MINT_ZKP", os.Getenv("MINT_ZKP"))
	if os.Getenv("MINT_ZKP") == "" {
		log.Printf("Could not resolve a MINT_ZKP environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("ASSERTINGWLIP", os.Getenv("ASSERTINGWLIP"))
	if os.Getenv("ASSERTINGWLIP") == "" {
		log.Printf("Could not resolve a ASSERTINGWLIP environment variable.")
		// os.Exit(1)
	}

	setEnvVariable("TRUST_DOMAIN", os.Getenv("TRUST_DOMAIN"))
	if os.Getenv("TRUST_DOMAIN") == "" {
		log.Printf("Could not resolve a TRUST_DOMAIN environment variable.")
		// os.Exit(1)
	}

}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".cfg")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
}

func introspect(datoken string, client http.Client) (introspectrsp FileContents) {
	
	// Introspect DA-SVID
	// var returnmsg string
	var rcvresp FileContents

	endpoint := "https://"+os.Getenv("ASSERTINGWLIP")+"/introspect?DASVID="+datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}
	// log.Printf(string(body))

	err = json.Unmarshal([]byte(body), &rcvresp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	introspectrsp = FileContents{
		Msg			: rcvresp.Msg,
		ZKP		 	:	rcvresp.ZKP,
		Returnmsg	:  "",
	}
return introspectrsp
}
