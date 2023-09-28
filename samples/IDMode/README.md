# Nested scheme using ID-mode

In this signature mode, the assumption is that a TTP identity provider (IdP) is available, enabling workloads to retrieve their own key pair and an identity document (e.g., X509 certificate/SVID). Also, each workload Wn along the path knows the identity of the next workload Wn+1. In this case, they can use its private key to generate signatures, allowing the token creation and appending in a non-repudiable manner. The public key could be taken from any verifiable identity document, with the "signing" key usage field set to true. This is expected to be the case when workloads establish mTLS connections, since the protocol requires certificates to be exchanged. Some implementations may allow that certificate to be extracted from the mTLS layer, whereas others may require it to be fetched at the application layer, as part of the token processing.

In this scenario, Wn may place the whole verifiable identity document as the "audience" claim in the payload, before conveying it to Wn+1. Since such credentials may be large themselves, this may create somewhat large tokens. However, this approach ensures that the receiver can easily verify that each workload identified in the token has signed it along the path without any additional information. Alternatively, Wn may fill the "audience" claim only with Wn+1 public key, sending the identity in a separate document, to allow Wn+1 to be identified further downstream. If the IdP provides a lookup service allowing workloads to fetch public keys from identifiers (and, possibly, cache them), it would be enough to use Wn+1’s identifier as "audience", leading to a multitude of possible trade-offs in terms of bandwidth usage (carrying credentials results in larger assertions), latency (using a lookup service that is contacted for verifying every assertion, without caching, increases latency), and statefulness (caching reduce latency, but are only useful if workloads store credentials locally).  

The most suitable choice depends, thus, on the requirements of the target environment. In terms of security, though, there are no trade-offs: any attempt to impersonate some workload W would require access to its private key, or subverting the underlying identity framework to issue fake credentials associated with W’s identifier. Figure 2 contains an example of an application using ID-mode to access user data.

![alt text](https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/idmode.jpg)


In the example, the process starts with an end user providing an OAuth token (1) to the front end that, by its side, sends it in a request to IdP for a new restricted token. The IdP mints the token tied with the received OAuth token (2), returning it to the front end, followed by its certificate. Then, every workload that needs to use the token in a request should append the mandatory claims and sign it, following the nested scheme, also appending the trusted bundle with its certificate. That is what the front-end (3) and middle-tier (4) do. Finally, the target workload receives the token and trust bundle using the certificates in sequential signature validation (5).

# Using the POC

</br>

## Setup your Environment

If you haven't already, follow the Setup Guide, on [/samples/README](../README.MD) 

After doing that, manually alter the `.cfg` file inside each workload folder accordingly:

- CLIENT_ID and CLIENT_SECRET: found in your okta application
- OKTA_DEVELOPER_CODE: a 7 number ID found in the URL of you okta dashboard (between dev- and -admin)
- HOST_IP: the IP set under "Sign-in redirect URIs" in your okta application
- WORKLOADIP: for each one of the workloads, configure it's IP with your host IP followed by a port (IP:PORT)

Here is a sample configuration:

```
CLIENT_ID=0oo643ull1KZl5yVe5d7
CLIENT_SECRET=yl5_6mIaTu5e1p5E70NazdFKNZ6bOhhWAzerdCOVc
OKTA_DEVELOPER_CODE=1234567
HOSTIP=192.168.0.100
ASSERTINGWLIP=192.168.0.100:8443
MIDDLETIERIP=192.168.0.100:8445
MIDDLE_TIER2_IP=192.168.0.100:8446
MIDDLE_TIER3_IP=192.168.0.100:8447
MIDDLE_TIER4_IP=192.168.0.100:8448
MIDDLE_TIER5_IP=192.168.0.100:8449
TARGETWLIP=192.168.0.100:8444
```

## Run the Application

Before running the application, you must start SPIRE, with: 
`cd /opt/spire`
`sudo ./start_spire_env.sh`

To run the application, simply use the command `docker-compose up --build`

After running it, open your browser on localhost:8080 and see if the application is working correctly

</br>

**Important**:

- SPIRE will keep running in background. Use `./kill` to stop the application. Notice that it will kill all the docker conatiners running in your machine
- Check the output for potential network errors during the download and preparation of the docker images
- Always check if your IP is correctly set in OKTA and in `.cfg`

