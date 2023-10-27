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

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/subject_workload/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Deposit Handler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds models.Balancetemp

	dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))
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

	endpoint := "https://" + os.Getenv("MIDDLETIERIP") + "/deposit?DASVID=" + os.Getenv("DASVIDToken") + "&deposit=" + r.FormValue("deposit")

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", os.Getenv("MIDDLETIERIP"), err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		fmt.Println("Return msg error:", funds.Returnmsg)
		Data = models.PocData{
			AppURI:          os.Getenv("HOSTIP"),
			Profile:         getProfileData(r),
			IsAuthenticated: isAuthenticated(r),
			HaveDASVID:      haveDASVID(),
			Returnmsg:       funds.Returnmsg,
		}

		local.Tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		Data = models.PocData{
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
