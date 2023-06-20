#ifndef HEADER_RSA_SIG_PROOF_H
# define HEADER_RSA_SIG_PROOF_H

#include <openssl/evp.h>
#include <openssl/bn.h>

/**
 * This struct corresponds to the BIGNUM elements of a proof of ownership of an RSA signature.
 * len is the number of components in the proof.
 * p are the proof components in the proof.
 * c are the commitment components in the proof.
 * Both p and c must have len elements.
 */
typedef struct {
    int len;
    BIGNUM **p;
    BIGNUM **c;
} rsa_sig_proof_t;


/**
 * Allocates space to a new proof of ownership of an RSA signature with proof_len components.
 * 
 * @param proof_len The number of components in the proof.
 * 
 * @return A pointer to the space allocated to the proof.
 */
rsa_sig_proof_t *rsa_sig_proof_new(int proof_len);

/**
 * Deallocates the space allocated to a proof of an RSA signature.
 * 
 * @param proof The proof to be deallocated. It is returned as NULL.
 */
void rsa_sig_proof_free(rsa_sig_proof_t *proof);


/**
 * Creates a proof of ownership of an RSA signature s with proof_len components, regarding the
 * public verification key e, with public modulus n with sec_len bits.
 * 
 * @param sec_len The number of bits of the RSA modulus.
 * @param proof_len The number of components in the proof.
 * @param s The signature to be proved ownership of.
 * @param e The public RSA exponent.
 * @param n The public RSA modulus.
 * 
 * @return A new proof represented as (rsa_sig_proof_t).
 */
rsa_sig_proof_t *rsa_sig_proof_prove(int sec_len, int proof_len, const BIGNUM *s, const BIGNUM *e, const BIGNUM *n);

/**
 * Verifies the correctness of a proof of ownership of an RSA signature to the message m,
 * regarding the public verification key e and the public modulus n.
 * 
 * @param proof The proof to be verified.
 * @param m The message which signature is proved to be owned.
 * @param e The public RSA exponent.
 * @param n The public RSA modulus.
 * 
 * @return 1 in case of success, 0 in case of failure, and -1 in case of error.
 */
int rsa_sig_proof_ver(rsa_sig_proof_t *proof, const BIGNUM *m, const BIGNUM *e, const BIGNUM *n);


/**
 * Creates a proof of ownership of an RSA signature sig (with length sig_len) with proof_len
 * components, regarding the public verification key vkey, with public modulus with sec_len bits.
 * This method encapsulates the signature generated with the OpenSSL's EVP interface.
 * 
 * @param sec_len The number of bits of the RSA modulus.
 * @param proof_len The number of components in the proof.
 * @param sig The signature to be proved ownership of.
 * @param sig_len The length of the signature
 * @param vkey The public verification key.
 * 
 * @return A new proof represented as (rsa_sig_proof_t).
 */
rsa_sig_proof_t *rsa_evp_sig_proof_prove(int sec_len, int proof_len, unsigned char *sig, unsigned int sig_len, EVP_PKEY *vkey);

/**
 * Verifies the correctness of a proof of ownership of an RSA signature to the message msg (with
 * length msg_len), regarding the public verification key vkey.
 * This method encapsulates the signature generated with the OpenSSL's EVP interface.
 * 
 * @param proof The proof to be verified.
 * @param msg The message which signature is proved to be owned.
 * @param msg_len The length of the message
 * @param vkey The public verification key.
 * 
 * @return 1 in case of success, 0 in case of failure, and -1 in case of error.
 */
int rsa_evp_sig_proof_ver(rsa_sig_proof_t *proof, unsigned char *msg, unsigned int msg_len, EVP_PKEY *vkey);

rsa_sig_proof_t *rsa_sig_proof_copy(int proof_len, rsa_sig_proof_t *proofsrc);

char* rsa_sig_proof2hex(int proof_len, rsa_sig_proof_t *proof);

rsa_sig_proof_t *rsa_sig_hex2proof(int proof_len, char *hexproof);

#endif /* HEADER_RSA_SIG_PROOF_H */
