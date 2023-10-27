package handlers

import (
	"bytes"
	// "crypto/rand"
	// "encoding/base64"
	// "encoding/hex"
	"encoding/json"
	"fmt"
	// "html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	// "net"
	"context"
	"time"
	// "bufio"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"crypto/ecdsa"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/subject_workload/models"
	

)

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Deposit Handler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds models.Balancetemp
	var temp models.Contents

	// validate received token and Certs
	receivedAssertion := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedAssertion), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received assertion: ", temp.DASVIDToken)

	rcvSVID := temp.IDArtifacts
	log.Print("Received SVID cert: ", rcvSVID)

	svidcerts := strings.SplitAfter(fmt.Sprintf("%s", rcvSVID), "-----END CERTIFICATE-----")
	log.Printf("%d certificates received!", len(svidcerts)-1)
	
	var i = 0
	var ecdsakeys []*ecdsa.PublicKey
	var cert *x509.Certificate
	for (i < (len(svidcerts)-1)) {
		log.Printf("Loading public key %d...", i)
		block, _ := pem.Decode([]byte(svidcerts[i]))
		cert, _ = x509.ParseCertificate(block.Bytes)

		ecdsakeys = append(ecdsakeys, cert.PublicKey.(*ecdsa.PublicKey))
		i++
	
	}

	valid := dasvid.ValidateECDSAIDassertion(temp.DASVIDToken, ecdsakeys)
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
	serverID := spiffeid.RequireTrustDomainFromString(os.Getenv("TRUST_DOMAIN"))

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

	updSVID := strings.Trim(strings.Join([]string{rcvSVID, fmt.Sprintf("%s", idartifact)}, ""), "[]")
	log.Println("Updated SVID bundle: %s", updSVID)
	
	// get audience 
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", os.Getenv("MIDDLETIERIP"), conf)
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
	assertion, err := dasvid.NewECDSAencode(assertionclaims, temp.DASVIDToken, clientkey)
	if err != nil {
		log.Fatal("Error generating signed ECDSA assertion!")
	} 
	log.Printf("Generated ECDSA assertion	: ", fmt.Sprintf("%s",assertion))
	log.Printf("Generated ID artifact		: ", fmt.Sprintf("%s",idartifact))

	values := map[string]string{"DASVIDToken": assertion, "IDArtifacts": updSVID}
	json_data, err := json.Marshal(values)
	if err != nil {
		log.Fatal(err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")
	response, err := client.Post(endpoint, "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		fmt.Println("Return msg error:", funds.Returnmsg)
		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			HaveDASVID:      haveDASVID(),
			Returnmsg:       funds.Returnmsg,
		}

		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		Data := models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			DASVIDClaims:    dasvidclaims,
			HaveDASVID:      haveDASVID(),
			Balance:         funds.Balance,
		}

		local.Tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}
