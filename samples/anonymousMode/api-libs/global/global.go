package global

import (
	"context"
	"log"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/constants"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/env"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/api-libs/options"
)

var (
	Ctx     context.Context
	Options *options.Options
)

func init() {
	options, err := options.InitOptions()
	if err != nil {
		log.Fatal("Options init errored: ", err.Error())
	}
	Options = options
	// InitGlobals()
}

func InitGlobals(opts *options.Options) {

	log.Print(" init global api options")
	env.Load(".cfg")

	Ctx = context.Background()

	opts.SocketPath =		env.String(constants.ENV_SOCKET_PATH, Options.SocketPath)
	opts.AssertingWLIP =	env.String(constants.ENV_ASSERTING_WL_IP, Options.AssertingWLIP)
	opts.MiddleTierIP =		env.String(constants.ENV_MIDDLE_TIER2_IP, Options.MiddleTierIP)
	opts.ProoLength =		env.Int(constants.ENV_PROOF_LENGTH, Options.ProoLength)
	opts.PemPath =			env.String(constants.ENV_PEM_PATH, Options.PemPath)
	opts.MintZKP =			env.String(constants.ENV_MINT_ZKP, Options.MintZKP)
	opts.AddZKP =			env.String(constants.ENV_ADD_ZKP, Options.AddZKP)
	opts.TrustDomain =		env.String(constants.ENV_TRUST_DOMAIN, Options.TrustDomain)
	opts.ClientID =			env.String(constants.ENV_CLIENT_ID, Options.ClientID)
	opts.ClientSecret =		env.String(constants.ENV_CLIENT_SECRET, Options.ClientSecret)
	opts.Issuer =			env.String(constants.ENV_ISSUER, Options.Issuer)
	opts.HostIP =			env.String(constants.ENV_HOST_IP, Options.HostIP)
	opts.TargetWLIP =		env.String(constants.ENV_TARGET_WL_IP, Options.TargetWLIP)

	log.Printf("api init options: %+v", opts)
}
