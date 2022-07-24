#ifndef RSA_BN_SIG_H
# define RSA_BN_SIG_H

#include <openssl/bn.h>

/**
 * Generates a textbook RSA signature from a message m, private key d, and public modulus n.
 * 
 * @param m The message.
 * @param n The public RSA modulus.
 * @param d The private RSA exponent.
 * 
 * @return The signature represented as a BIGNUM.
 */
BIGNUM *rsa_bn_sig(const BIGNUM *m, const BIGNUM *n, const BIGNUM *d);

/**
 * Verifies a textbook RSA signature s to the message m, using the public key e and the public
 * modulus n.
 * 
 * @param s The signature.
 * @param m The message.
 * @param n The public RSA modulus.
 * @param e The public RSA exponent.
 * 
 * @return 1 if the signature is valid, 0 if it is invalid, and -1 in case of error.
 */
int rsa_bn_ver(const BIGNUM *s, const BIGNUM *m, const BIGNUM *n, const BIGNUM *e);

#endif /* RSA_BN_SIG_H */
