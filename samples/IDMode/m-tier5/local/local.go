package local

import (
	"log"

	api "github.com/hpe-usp-spire/signed-assertions/IDMode/api-libs/global"
	alOps "github.com/hpe-usp-spire/signed-assertions/IDMode/api-libs/options"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier5/options"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier5/monitoring-prom"
)

var Options *alOps.Options

func init() {
	monitor.RegisterMetrics()
	log.Print("global init")

	options, err := options.InitOptions()
	if err != nil {
		log.Fatal("Options init errored: ", err.Error())
	}

	Options = options
}

func InitGlobals() {
	log.Print("init global")
	api.InitGlobals(Options)
}
