//go:build linux && cgo
// +build linux,cgo

package main

/*
#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "./poclib/svid/rsa_sig_proof.h"
#include "./poclib/svid/rsa_bn_sig.h"
#include "./poclib/svid/rsa_sig_proof_util.h"

*/
import "C"

import (
	"context"
	"log"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/Assertingwl-mTLS/controller"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/Assertingwl-mTLS/local"
	// SPIFFE
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// local.InitGlobals()

	log.Printf("final init options: %+v", local.Options)
	log.Printf("PRINTAO NOVO TA")
	// controller.WLController(ctx, global.Options)
	controller.WLController(ctx)
}
