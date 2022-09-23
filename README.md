# HPE-USP - SPIFFE - SPIRE 
This repository is part of HPE/USP SPIFFE project. 

# Main Components
## Client
Client is a prototype that can interact with a running asserting-wl and also perform solo functions as generate, append and validate ECDSA/Schnorr signed assertions and tokens. To be able to interact with asserting-wl using spiffe-mTLS, it is necessary a running spire server/agent in the environment and a registration entry in SPIRE associated to the user that will execute the client. Eg:

```
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/myuser \
    -selector unix:user:myuser
```

Client have also many functions related to assertions and token generation and validation, using ECDSA or Schnorr signatures. To start the it, run ./startapp.sh. It will start keyserver container and build assertgen in /client. Run assertgen help for more informations.

```
./assergen help
```

## Poclib
Golang package including necessary functions related to DA-SVID, assertions, tokens, zkp, validations etc...  It can be integrated in Golang projects (as exemplified in DASVID_PoC_V0 PoC), offering support to the token nested model, ECDSA/Schnorr signatures and Validation, and others (check code).

## Keyserver
Docker container that acts as a key storage (a.k.a. Key Directory Service) in Proof-of-Concept scenario. Have 2 main functions: Addkey / GetKey, used by assertgen to store ECDSA public keys, necessary in ECDSA validation step (if the key is not included in token).

# OLD - --- -- -- --
# Asserting Workload --prototype--  
Asserting Workload is the main component that is responsible for Oauth token validation and DA-SVID minting. To perform its tasks, Asserting WL exposes an API with the necessary endpoints described bellow. All API responses are in JSON format.

To access the API, clients must stablish a mTLS connection with Asserting Workload using its SVID. Asserting workload accepts any connection originated from its trust domain, and clients should accept connections only from specific predefined SPIFFE-IDs (Asserting Workload).  

When connected, clients can access /keys, /mint and /introspect endpoints.

# /keys
This endpoint does not require any parameter, and returns the public key set necessary to validate DA-SVIDs.

# /mint
Require a OKTA or Google OAuth token as _AccessToken_ parameter. 

When a mint call is received, the Asserting Workload validate the OAuth token received. If the token is valid, it fetchs the SPIFFE-ID from the current mTLS session and uses it as DA-SVID subject claim. Asserting Workload also fetchs its own SPIFFE-ID and use it as DA-SVID issuer claim.  

After DA-SVID claims generation, the token is signed with Asserting Workload private key, that could be its SVID or another specific key. The current implementation uses a specific key, localized in ./keys.  

In the end, the Asserting Workload sends to client Oauth token expiration and signature validation results and the generated DA-SVID.

# /introspect
Requires a DA-SVID as parameter.  

This endpoint return the DA-SVID original claims and a proof that a valid OAuth token was used to generate that DA-SVID.
