# Anonymous-mode
In this mode, either by application option or due to the unavailability of an IdP, workload Wn can not validate the identity of workload Wn+1. Hence, the solution is limited to “bearers” rather than univocally identifying workloads. The construction of this scheme can follow a Biscuits-like approach or use a concatenation scheme.

As there are two different schemes to be applied, we had chosen for the anonymous mode PoC the concatenated scheme, due to having more challenges and benefits in terms of performance and token size. Although, assertgen CLI can be used to create a token using all the different schemes developed.

## Biscuits scheme
One possible approach with this characteristic, adopted in related solutions like Biscuits, is depicted in Figure 3. In this scenario, as there is no IdP available, Wn itself assumes the role of certificate issuer: it creates a key pair on the fly and sends the private key to Wn+1 using a secure channel; therefore, similarly to the case with an identity framework, Wn+1 can use its (newly issued) private key to assert the fact that it has received the corresponding token from Wn. In this scenario, Wn would fill the token “issuer” claim with its public key and "audience" claim with Wn+1 newly issued public key, before signing that assertion and conveying it to Wn+1. 

![Biscuits scheme](https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/biscuits.jpg)

Even though this approach binds that assertion to the intended target, the absence of a reliable identity framework still allows some impersonation attacks. For example, a malicious workload Wn might pretend to have sent an assertion A to some arbitrary Wn+1 by (I) filling its “audience” claim with Wn+1’s identifier together with a bogus public key, (II) signing the resulting assertion as if the signature was done by Wn+1, and (III) convey the fake assertion further downstream.

## Concatenated scheme
Alternatively, when appending a token, instead of generating a new key pair during the signature process, it is possible to apply a concatenation scheme by using part of the previous signature as the private key, as presented in Figure 4. The process starts with Wn creating a new token T0 with its private key sk0, containing its public key in “issuer” claim, and sending it to Wn+1 (1). As the digital signatures are composed of two parts, usually called "r" and "s", Wn+1 extracts the "s" part of the previous signature Sn (2), filling the token "issuer" claim with its public key and signing the resulting payload using Sn+1 as private key (3). This scheme results in a token where only the last signature is complete (with "r" and "s" parts), while all previous are partial signatures containing  just the "r" part.

![Concatenated scheme](https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/conc_sig.jpg)

It is important to note that in a concatenated scheme there is no need (and it is not possible) to add the public key in "audience" claim, as the correspondent private key depends on the signature generation. Although, it is not a problem: the cryptographic scheme grants that only the correct key, derived from previous signature, can result in a valid concatenated signature.

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

