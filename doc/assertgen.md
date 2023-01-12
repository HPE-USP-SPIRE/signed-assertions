# Assertgen

## _Command-Line Interface (CLI)_ to token generation

Assertgen is a CLI prototype for PocLib, that can perform different tasks using the proposed token nested model. It was developed during Phase 2 of HPE/USP Transitive Identity & Embedded Claims project to support the specification and test of the proposed solution. Considering this, new features were constantly being added throughout the project.

It main features can be grouped as follows:

- General functions
-  Asserting Workload Interactions
-  ECDSA token creation and validation
-  Standard Schnorr token creation and validation
-  Concatenated Schnorr token creation and validation
-  Tracing model (poc scenario)
-  Selector-based assertion (poc scenario)

### General functions

`./assergen help`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`help`|string|yes|Return a list of parameters and their descriptions|

`./assergen print <token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<token>`|string|yes|Print given base64 nested token payloads and signatures|

### Asserting Workload Interactions

The asserting workload is a specifically designed Identity Provider (IdP) to mint, validate, and generate a more restricted token and ZKP based in a valid OKTA OAuth token. The PoC documentation can provide details about asserting workload construction and functionalities.
Assertgen can interact with a running instance of [asserting-wl](link_to_PoC_md_file) (IdP developed in PoC). To be able to interact with asserting-wl using spiffe-mTLS, it is necessary a running spire server/agent in the environment and a registration entry in SPIRE associated to the user that will execute the client. Eg:

```console
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/myuser \
    -selector unix:user:myuser
```


After that, its endpoints are acessible through assertgen, using the following commands:

`./assergen keys`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`keys`|string|yes|Contact asserting workload and return its public key in JWKS format|

`./assergen mint <OAuth_token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<OAuth_token>`|string|yes|OKTA OAuth token to be used as reference in the generation of a new JWT ECDSA token. Mint a token allowing the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen ecdsaassertion <OAuth_token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<OAuth_token>`|string|yes|OKTA OAuth token to be used as reference in the generation of a new ECDSA nested token. The objective is to allow the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen mintassertion <OAuth_token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<OAuth_token>`|string|yes|OKTA OAuth token to be used as reference in the generation of a new Schnorr nested token. The objective is to allow the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen validate <dasvid>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<dasvid>`|string|yes|Ask asserting workload to validate the given dasvid. Only accepts JWT ECDSA tokens. It will return the validity considering expiration time and signature|

`./assergen zkp <dasvid>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<dasvid>`|string|yes|Ask asserting workload to return a ZKP of the OAuth token that is behind the given dasvid. It will return the ZKP in JSON format considering PoC configurations|

### ECDSA token creation and validation

`./assergen ecdsagen <assertionKey> <assertionValue> <spiffeid/svid>`
Allows the creation of a new ECDSA token, containing given key/value.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<spiffeid/svid/anonymous>`|string|yes|The identity model to be used. spiffeid set the identities as their respective SPIFFE-ID; svid set the identities as their respective certificates; anonymous uses the public keys as the identities|

`./assergen ecdsaadd <originaltoken> <assertionKey> <assertionValue> <spiffeid/svid>`
Allows to add a new key/value to an existing token, using the nested model.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<originaltoken>`|string|yes|The original token to which the new key/value will be added|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<spiffeid/svid/anonymous>`|string|yes|The identity model to be used. spiffeid set the identities as their respective SPIFFE-ID; svid set the identities as their respective certificates; anonymous uses the public keys as the identities|

`./assergen multiappend <originaltoken> <assertionKey> <assertionValue> <howmany> <spiffeid/svid>`
Append a specific number of ECDSA assertions to an existing token (for test purposes in some scenarios).
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<originaltoken>`|string|yes|The original token to which the new key/value will be added|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<howmany>`|integer|yes|The number of nested tokens to be created, using given key /value.|
|`<spiffeid/svid/anonymous>`|string|yes|The identity model to be used. spiffeid set the identities as their respective SPIFFE-ID; svid set the identities as their respective certificates; anonymous uses the public keys as the identities|

`./assergen ecdsaver <token>`
Verify all ECDSA nested token signatures, starting from last one.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<token>`|string|yes|The token to be verified|

`./assergen ecdsapq <token>`
Create the ECDSA nested token and an additional token using Dillithium post-quantum algorithm, for PoC purposes.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<howmany>`|integer|yes|The number of nested tokens to be created, using given key /value.|
|`<spiffeid/svid/anonymous>`|string|yes|The identity model to be used. spiffeid set the identities as their respective SPIFFE-ID; svid set the identities as their respective certificates; anonymous uses the public keys as the identities|

# License
This project is licensed under the terms of the Apache 2.0 license. It was developed to support the HPE/USP Transitive Identity & Embedded Claims project, and it is important to not that it may require some specific configurations to run properly. The command-line tool assertgen can be used as an example of Poclib usage.
