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
