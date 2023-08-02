package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/models"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/local"
)

func ProfileHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Profile Handler")

	Data = models.PocData{
		AppURI:          os.Getenv("HOSTIP"),
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:      haveDASVID(),
	}
	local.Tpl.ExecuteTemplate(w, "profile.gohtml", Data)
}
