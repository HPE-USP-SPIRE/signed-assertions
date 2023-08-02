package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	// "github.com/spiffe/go-spiffe/v2/svid/x509svid"

	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/models"
	"go.dedis.ch/kyber/v3/group/edwards25519"


)

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	var curve = edwards25519.NewBlakeSHA256Ed25519()
	var g = curve.Point().Base()

	defer timeTrack(time.Now(), "Deposit Handler")

	var funds models.Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()
	oldmain 		:= os.Getenv("DASVIDToken")
	parts 			:= strings.Split(oldmain, ".")		

	var assertion string

	// Retrieve signature from originaltoken 
	prevsignature, err := dasvid.String2schsig(parts[1])
	if err != nil {
		log.Fatalf("Error converting string to schnorr signature!")
	} 
	privateKey := prevsignature.S
	// Discard sig.S
	parts[len(parts) -1], err = dasvid.Point2string(prevsignature.R)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	oldmain = strings.Join(parts, ".")
	publicKey := curve.Point().Mul(privateKey, g)
	// fmt.Println("Generated publicKey: ", publicKey)
		
	// Issuer
	issuer, err := dasvid.Point2string(publicKey)
	if err != nil {
		log.Fatalf("Error decoding point string!")
	} 

	// Issuer ID
	clientSVID 		:= dasvid.FetchX509SVID()
	clientID 		:= clientSVID.ID.String()

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
	assertionclaims := map[string]interface{}{
		"iss"		:		issuer,
		"iid"		:		clientID,
		"iat"		:	 	issue_time,
	}
	assertion, err = dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
	if err != nil {
		log.Fatal("Error generating signed SCHNORR assertion!")
	}
	log.Printf("Generated assertion: ", fmt.Sprintf("%s",assertion))

	endpoint := "https://"+os.Getenv("MIDDLETIERIP")+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")
	response, err := client.Get(endpoint)
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
			AppURI:				os.Getenv("HOSTIP"),
			Profile:			getProfileData(r),
			IsAuthenticated:	isAuthenticated(r),
			HaveDASVID:			haveDASVID(),
			Returnmsg:			funds.Returnmsg,
		}

		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		Data := models.PocData{
			AppURI:				os.Getenv("HOSTIP"),
			Profile:			getProfileData(r),
			IsAuthenticated:	isAuthenticated(r),
			DASVIDClaims:		dasvidclaims,
			HaveDASVID:			haveDASVID(),
			Balance:			funds.Balance,
		}

		local.Tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}
