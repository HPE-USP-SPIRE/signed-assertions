module github.com/marco-developer/dasvid

require github.com/marco-developer/dasvid/poclib v1.0.0

replace github.com/marco-developer/dasvid/poclib v1.0.0 => ./poclib

go 1.17

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/gorilla/sessions v1.2.1
	github.com/okta/okta-jwt-verifier-golang v1.1.2
	github.com/okta/samples-golang v0.0.0-20211027153507-a908fb6101b2
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	github.com/goccy/go-json v0.3.5 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.7 // indirect
	github.com/lestrrat-go/httpcc v1.0.0 // indirect
	github.com/lestrrat-go/iter v1.0.0 // indirect
	github.com/lestrrat-go/jwx v1.1.1 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.10 // indirect
	github.com/zeebo/errs v1.2.2 // indirect
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620 // indirect
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f // indirect
	golang.org/x/text v0.3.3 // indirect
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98 // indirect
	google.golang.org/grpc v1.33.2 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
)
