package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/local"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/models"
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
