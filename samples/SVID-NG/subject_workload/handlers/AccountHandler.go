package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/subject_workload/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/subject_workload/local"
)

func AccountHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Account Handler")

	log.Print("Contacting Assertingwl to retrieve DA-SVID... ")

	receivedDASVID := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedDASVID), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}
	log.Print("Received DA-SVID: ", receivedDASVID)

	if (*temp.OauthSigValidation == false) || (*temp.OauthExpValidation == false) {

		returnmsg := "Oauth token validation error"

		Data = models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			Returnmsg:       returnmsg,
		}

		log.Printf(returnmsg)
		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		os.Setenv("DASVIDToken", temp.DASVIDToken)

		dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))

		Data = models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			DASVIDToken:     temp.DASVIDToken,
			DASVIDClaims:    dasvidclaims,
			HaveDASVID:      haveDASVID(),
			SigValidation:   fmt.Sprintf("%v", temp.OauthSigValidation),
			ExpValidation:   fmt.Sprintf("%v", temp.OauthExpValidation),
		}

		local.Tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}

func getdasvid(oauthtoken string) string {

	defer timeTrack(time.Now(), "Get DASVID")

	// Asserting workload will validate oauth token, so we dont need to do it here.
	// stablish mtls with asserting workload and call mint endpoint, passing oauth token
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

	var endpoint string
	token := os.Getenv("oauthtoken")
	log.Println("OAuth Token: ", token)
	endpoint = "https://" + local.Options.AssertingWLIP + "/mint?AccessToken=" + token
	log.Println("local.Options.AssertingWLIP: ", local.Options.AssertingWLIP)

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("ASSERTINGWLIP"), err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}
	log.Println("Asserting-wl response: ", fmt.Sprintf("%s", body))
	return fmt.Sprintf("%s", body)
}
