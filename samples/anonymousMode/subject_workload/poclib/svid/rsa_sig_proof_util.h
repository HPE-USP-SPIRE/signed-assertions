#ifndef UTIL_H
# define UTIL_H

#include <openssl/bn.h>
#include <openssl/evp.h>

/**
 * Prints to stdout an OpenSSL BIGNUM.
 * Used in debug.
 */
void print_bn(BIGNUM *n);


/**
 * Extracts to BIGNUM the public modulus n and the public exponent e from an EVP public
 * verification key vkey.
 * 
 * @param n The extracted public RSA modulus.
 * @param e The extracted public RSA exponent.
 * @param vkey The public verification key.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_vkey_extract_bn(BIGNUM **n, BIGNUM **e, EVP_PKEY *vkey);

/**
 * Extracts to BIGNUM the private exponent d from an EVP private signing RSA key skey.
 * 
 * @param d The extracted private RSA exponent.
 * @param skey The private signing key.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_skey_extract_bn(BIGNUM **d, EVP_PKEY *skey);

/**
 * Extracts to BIGNUM the signature s from an EVP generated signature sig (with length sig_len).
 * 
 * @param s The extracted signature.
 * @param sig The signature as a string.
 * @param sig_len The length of the signature.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_sig_extract_bn(BIGNUM **s, unsigned char *sig, size_t sig_len);

/**
 * Extracts to BIGNUM the message m, after encoding and padding the digest of the plaintext msg
 * (with length msg_len), using the public RSA modulus n.
 * 
 * @param m The extracted (encoded and with padding) message m.
 * @param msg The plaintext to be extracted.
 * @param msg_len The length of the plaintext.
 * @param n The public RSA modulus.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_msg_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, BIGNUM *n);

/**
 * Extracts to BIGNUM the message m, after encoding and padding the digest of the plaintext msg
 * (with length msg_len), using the public RSA modulus from the public verification key vkey.
 * 
 * @param m The extracted (encoded and with padding) message m.
 * @param msg The plaintext to be extracted.
 * @param msg_len The length of the plaintext.
 * @param vkey The public verification key.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_msg_evp_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, EVP_PKEY *vkey);

#endif /* UTIL_H */
