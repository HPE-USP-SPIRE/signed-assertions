#include <stdio.h>
#include <openssl/bn.h>
#include "rsa_bn_sig.h"

/**
 * Generates a textbook RSA signature from a message m, private key d, and public modulus n.
 * 
 * @param m The message.
 * @param n The public RSA modulus.
 * @param d The private RSA exponent.
 * 
 * @return The signature represented as a BIGNUM.
 */
BIGNUM *rsa_bn_sig(const BIGNUM *m, const BIGNUM *n, const BIGNUM *d) {
    BIGNUM *s = NULL;
    BN_CTX *bnctx = NULL;

    if(m == NULL || n == NULL || d == NULL) {
        printf("Invalid parameters to sign\n");
        return NULL;
    }

    bnctx = BN_CTX_secure_new();

    s = BN_new();

    BN_mod_exp(s, m, d, n, bnctx);

    BN_CTX_free(bnctx);

    return s;
}

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
int rsa_bn_ver(const BIGNUM *s, const BIGNUM *m, const BIGNUM *n, const BIGNUM *e) {
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *f = NULL;

    if(s == NULL || m == NULL || n == NULL || e == NULL) {
        printf("Invalid parameters to verify\n");
        return -1;
    }

    bnctx = BN_CTX_secure_new();
    f = BN_new();

    BN_mod_exp(f, s, e, n, bnctx);

    if( BN_cmp(f, m) == 0 ) {
        ret = 1;
    }

    BN_CTX_free(bnctx);

    return ret;
}
