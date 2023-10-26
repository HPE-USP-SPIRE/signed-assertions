# Optimizing the WLs' dependencies

1. List the common dependencies to all the WL in the sample, then use diff in the WL's go.mod to elect one go.mod
2. In a new dir, called common: copy a base go.mod from some WL and: a)change module's name; b) remove local require/replace (e.g., poclib). They are in the beginninf of the file, but look for similar references in the file.
3. Create a common dockerfile (copy ref)
4. Use FROM... in the other dockerfiles and remove unnecessary commands (copy dockerfile from an already adapted WL, make 3 changes: COPY, LABEL, EXPOSE)

## Notes

- Even if the common image has all the dependencies of a certain WL. This Wl still needs a go.mod with its dependencies
- Even in WLs that don't have new dependencies (apart from the common ones), you can use go mod downlaod in the Dockerfile. It won't download these dependencies again.

## SVID-NG

Asserting, target and MT are the same. MT's go.mod used in common.

---

## Tests (SVID-NG)

### Asserting

"github.com/spiffe/go-spiffe/v2/spiffeid"
"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
"github.com/spiffe/go-spiffe/v2/workloadapi"
"github.com/gorilla/mux"

"github.com/spiffe/go-spiffe/v2/svid/x509svid" (the other WLs also use github.com/spiffe/go-spiffe/v2/)

### Subject

"github.com/spiffe/go-spiffe/v2/spiffeid"
"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
"github.com/spiffe/go-spiffe/v2/workloadapi"

"github.com/okta/samples-golang/okta-hosted-login/utils"
"github.com/gorilla/sessions"
"github.com/okta/okta-jwt-verifier-golang"

### MT1

"github.com/spiffe/go-spiffe/v2/spiffeid"
"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
"github.com/spiffe/go-spiffe/v2/workloadapi"
"github.com/gorilla/mux"

### Target

"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
"github.com/spiffe/go-spiffe/v2/spiffeid"
"github.com/spiffe/go-spiffe/v2/workloadapi"
"github.com/gorilla/mux"
