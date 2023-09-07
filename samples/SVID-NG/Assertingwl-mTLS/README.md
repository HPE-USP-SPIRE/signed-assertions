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
