#ifndef RSA_EVP_SIG_H
# define RSA_EVP_SIG_H

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/**
 * Generate an RSA signature key pair, skey private key and vkey public key, with a modulus of
 * sec_len bits.
 * 
 * @param skey The generated private key.
 * @param vkey The generated public key.
 * @param sec_len The number of bits in the module.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_evp_keygen(EVP_PKEY **skey, EVP_PKEY **vkey, unsigned int sec_len);

/**
 * Creates na RSA signature sig (with length sig_len) to the message msg (with length msg_len),
 * with the RSA signing key skey, using a SHA256 message digest.
 * 
 * @param sig The generated signature.
 * @param sig_len The length of the generated signature.
 * @param msg The message to be signed.
 * @param msg_len The length of the message.
 * @param skey The private (signing) key.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_evp_sign(unsigned char **sig, size_t *sig_len, unsigned char *msg, unsigned int msg_len,
                 EVP_PKEY *skey);

/**
 * Verifies an RSA signature sig (with length sig_len) to the message msg (with length msg_len),
 * using the public verification key vkey.
 * 
 * @param sig The signature to be verified.
 * @param sig_len The length of the signature.
 * @param msg The message signed to.
 * @param msg_len The length of the message.
 * @param vkey The public verification key.
 * 
 * @param 1 in case of success, 0 in case of failure, and -1 in case of error.
 */
int rsa_evp_verify(unsigned char *sig, size_t sig_len, unsigned char *msg, unsigned int msg_len,
                   EVP_PKEY *vkey);

#endif /* RSA_EVP_SIG_H */
