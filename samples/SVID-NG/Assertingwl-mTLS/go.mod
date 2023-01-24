module github.com/marco-developer/dasvid

require github.com/marco-developer/dasvid/poclib v1.0.0

replace github.com/marco-developer/dasvid/poclib v1.0.0 => ./poclib

go 1.17

require github.com/spiffe/go-spiffe/v2 v2.0.0-beta.10

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/zeebo/errs v1.2.2 // indirect
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620 // indirect
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98 // indirect
	google.golang.org/grpc v1.33.2 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
