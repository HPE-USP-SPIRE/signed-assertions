# Assertgen
Assertgen is a CLI that can perform different tasks using the poclib Go package.

## Requirements (tested)

- GNU/Linux (Debian 11)
- Docker (20.10.11)
- Go (1.16.9)

Some of assertgen commands requires a running local SPIRE instance to retrieve necessary key pairs and certificates. Others are to interact with IdP (asserting-wl) in proof of concept scenarios. 

The _.cfg_ file inside each scenario directory contains the basic configuration necessary to a local execution. 

The script startapp.sh compile assertgen and create and run a container to mock an IdP. It is useful in demo scenarios where we need an IdP to store and return public keys.

Details about how to install the requirements and perform necessary configurations to proof of concept execution can be found in https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/Poc-Install.md.  

More details about each assertgen function can be found in next Section.

## _Command-Line Interface (CLI)_ to token generation

It was developed during Phase 2 of HPE/USP Transitive Identity & Embedded Claims project to support the specification and test of the proposed solution. Considering this, new features were constantly being added throughout the project.

It main features can be grouped as follows:

- General functions
- Asserting Workload Interactions
- ECDSA token creation and validation
- Standard Schnorr token creation and validation
- Concatenated Schnorr token creation and validation
- Standard tracing model (poc scenario)
- Selector-based assertion (poc scenario)

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
|`<OAuth_token>`|string|yes|Contact asserting workload, passing an OKTA OAuth token to be used as reference in the generation of a new JWT ECDSA token. The minted token allows the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen ecdsaassertion <OAuth_token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<OAuth_token>`|string|yes|Contact asserting workload, passing an OKTA OAuth token to be used as reference in the generation of a new ECDSA nested token. The minted token allows the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen mintassertion <OAuth_token>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<OAuth_token>`|string|yes|Contact asserting workload, passing an OKTA OAuth token to be used as reference in the generation of a new Schnorr nested token. The minted token allows the workload identified in subject claim to act in behalf of the end user identified by given OAuth token|

`./assergen validate <dasvid>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<dasvid>`|string|yes|Contact asserting workload, passing an dasvid to be validated. Only accepts JWT ECDSA tokens. It will return the validity considering expiration time and signature|

`./assergen zkp <dasvid>`
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<dasvid>`|string|yes|Contact asserting workload, passing an dasvid and expecting a ZKP of the RSA signature of OAuth token that is behind the given dasvid. It will return the OAuth claims and the ZKP in JSON format, considering PoC configurations|

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

### Standard Schnorr token creation and validation

`./assergen schgen <assertionKey> <assertionValue>`  
Create a new schnorr nested token containing key:value, with no specific audience. A key pair is generated, being the issuer public key stored in 'iss' claim.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |

`./assergen schadd <originaltoken> <assertionKey> <assertionValue>`  
Create a new schnorr nested token containing key:value. A new key pair is generated, being the public key stored in 'aud' (audience) claim. The corresponding private key needs to be passed off-band (similar to Biscuits approach)
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<originaltoken>`|string|yes|The original token to which the new key/value will be added|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |

`./assergen schver <token>`  
Validate Schnorr nested token signatures.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<token>`|string|yes|The token to be validated|

### Concatenated Schnorr token creation and validation

This set of functions allow to create nested tokens using the concatenated Schnorr signature and validation schemes, that allows to use part of previous signature as private key of the next, reducing the resulting token size, avoiding key pair creation, and reducing the validation execution time.

`./assergen concatenate <originaltoken> <assertionKey> <assertionValue>`  
Append an assertion to an existing token using concatenated Schnorr signature scheme and previous signature.S as key.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<originaltoken>`|string|yes|The original token to which the new key/value will be added using concatenated model|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |

`./assergen ggschnorr <token>`  
Uses the concatenated signature validation scheme to validate the given nested token
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<token>`|string|yes|The original concatenated schnorr nested token to be validated|

### Standard Schnorr tracing model 

This set of functions allows to create a token tracing model using a issuer / audience verification. In this model, a token is aways minted with an aud claim, that must be the public key to be used in the validation of next token. The keys are generated based in a password.

`./assertgen tracegen <assertionKey> <assertionValue> <secretkey> <nextsecretkey>`  
Generate a new schnorr nested token containing key:value and audience
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<secretkey>`|string|yes|The current token secretkey|
|`<nextsecretkey>`|string|yes|The secret key to be used to in next token generation. Must be send to next workload|

`./assertgen traceadd  <tracetoken> <assertionKey> <assertionValue> <sourceprivatekey> <nextsecretkey>`  
Append a new schnorr signed assertion containing key:value and audience to an existing token
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<tracetoken>`|string|yes|The token to be appended|
|`<assertionKey>`|string|yes|The key to be added in token claims|
|`<assertionValue>`|string|yes|The correspondent value to be added in 'key' claim |
|`<sourceprivatekey>`|string|yes|The private key to be used to sign current token|
|`<nextsecretkey>`|string|yes|The secret key to be used to in next token generation|

`./assertgen tracever  <token>`  
Verify nested token Schnorr std signatures and also validate if iss/aud links matches.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<token>`|string|yes|The token to be validated|

### Selector-based assertion (poc scenario)

`./assertgen selectors <spiffeid/svid/anonymous>`  
Generate an ECDSA token, signed with workload SVID private key, containing its selectors, used in its attestation process, performed by SPIRE-Agent.
|Parameter|Type|Required|Description|
|--|--|--|--|
|`<spiffeid/svid/anonymous>`|string|yes|The identity model to be used. spiffeid set the identities as their respective SPIFFE-ID; svid set the identities as their respective certificates; anonymous uses the public keys as the identities|

# License
This project is licensed under the terms of the Apache 2.0 license. It was developed to support the HPE/USP Transitive Identity & Embedded Claims project, and it is important to not that it may require some specific configurations to run properly. The command-line tool assertgen can be used as an example of Poclib usage.
