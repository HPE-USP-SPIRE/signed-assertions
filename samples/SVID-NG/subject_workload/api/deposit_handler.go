package api

import (

	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"context"
	"time"
	_ "crypto/sha256"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	dasvid "github.com/marco-developer/dasvid/poclib"
	
	"SVID-NG/utils"
	"SVID-NG/types"
)


func init() {
    utils.Tpl = template.Must(template.ParseGlob("./templates/*"))
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {
	defer utils.TimeTrack(time.Now(), "Deposit Handler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds types.Balancetemp

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

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		fmt.Println("Return msg error:", funds.Returnmsg)
		utils.Data = types.PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		utils.GetProfileData(r),
			IsAuthenticated: 		utils.IsAuthenticated(r),
			HaveDASVID:				utils.HaveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		utils.Tpl.ExecuteTemplate(w, "home.gohtml", utils.Data)	
		
	} else {

		utils.Data = types.PocData{
			AppURI:					os.Getenv("HOSTIP"),
			Profile:         		utils.GetProfileData(r),
			IsAuthenticated: 		utils.IsAuthenticated(r),
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				utils.HaveDASVID(),
			Balance:				funds.Balance,
		}
		
		utils.Tpl.ExecuteTemplate(w, "account.gohtml", utils.Data)
	}
}