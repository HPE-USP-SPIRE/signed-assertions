module github.com/hpe-usp-spire/signed-assertions/phase3/target-wl

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/hpe-usp-spire/signed-assertions/lsvid v0.0.0-00010101000000-000000000000
	github.com/hpe-usp-spire/signed-assertions/phase3/api-libs v0.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.1.6
)

replace github.com/hpe-usp-spire/signed-assertions/phase3/api-libs => ./api-libs

replace github.com/hpe-usp-spire/signed-assertions/poclib => ./poclib

replace github.com/hpe-usp-spire/signed-assertions/lsvid => ./lsvid

replace github.com/spiffe/go-spiffe/v2 => ./go-spiffe/v2

replace google.golang.org/grpc => google.golang.org/grpc v1.53.0

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/smartystreets/assertions v1.13.1 // indirect
	github.com/smartystreets/goconvey v1.8.0 // indirect
	github.com/zeebo/errs v1.3.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20230223222841-637eb2293923 // indirect
	google.golang.org/grpc v1.59.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
