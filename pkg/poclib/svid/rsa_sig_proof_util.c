#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/* The following encondings are defined in RFC 3447, section 9.2, and are used when encoding
 * digests to be signed with the RSA algorithm with PKCS1 encoding, and SHA message digests. */

unsigned char sha256_der_encoding[] = 
    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
     0x05, 0x00, 0x04, 0x20, };

unsigned char sha384_der_encoding[] = 
    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
     0x05, 0x00, 0x04, 0x30, };

unsigned char sha512_der_encoding[] = 
    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
     0x05, 0x00, 0x04, 0x40, };


/**
 * Prints to stdout an OpenSSL BIGNUM.
 * Used in debug.
 */
void print_bn(BIGNUM *n) {
    int i;
    unsigned char *buf = NULL;

    if(n == NULL) {
        printf("NULL\n");
        return;
    }

    buf = (unsigned char *) OPENSSL_malloc(BN_num_bytes(n));

    BN_bn2bin(n, buf);

    for(i = 0; i < BN_num_bytes(n)-1; i++) {
        printf("%02X", buf[i]);
        if((i+1)%32 == 0) printf("\n");
        else if((i+1)%8 == 0) printf(" ");
    }
    printf("%02X\n", buf[BN_num_bytes(n)-1]);

    OPENSSL_free(buf);
}

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
int rsa_vkey_extract_bn(BIGNUM **n, BIGNUM **e, EVP_PKEY *vkey) {
    int ret = 0;
    RSA *rsa = NULL;

    if(n == NULL || e == NULL || vkey == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    if(*n == NULL) *n = BN_new();
    if(*e == NULL) *e = BN_new();

    rsa = EVP_PKEY_get1_RSA(vkey);

    if(rsa == NULL) {
        printf("Unable to read RSA key\n");
        ret = -1;
        goto vkey_ext_err;
    }

    BN_copy(*n, RSA_get0_n(rsa));
    BN_copy(*e, RSA_get0_e(rsa));

    if(*n == NULL || *e == NULL) {
        printf("Unable to extract RSA key\n");
        ret = -1;
        goto vkey_ext_err;
    }

    return 1;

vkey_ext_err:
    if(*n != NULL) BN_free(*n);
    if(*e != NULL) BN_free(*e);

    return ret;
}

/**
 * Extracts to BIGNUM the private exponent d from an EVP private signing RSA key skey.
 * 
 * @param d The extracted private RSA exponent.
 * @param skey The private signing key.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_skey_extract_bn(BIGNUM **d, EVP_PKEY *skey) {
    int ret = 0;
    RSA *rsa = NULL;

    if(d == NULL || skey == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    if(*d == NULL) *d = BN_secure_new();

    rsa = EVP_PKEY_get1_RSA(skey);

    if(rsa == NULL) {
        printf("Unable to read RSA key\n");
        ret = -1;
        goto skey_ext_err;
    }

    BN_copy(*d, RSA_get0_d(rsa));

    if(*d == NULL) {
        printf("Unable to extract RSA key\n");
        ret = -1;
        goto skey_ext_err;
    }

    return 1;

skey_ext_err:
    if(*d != NULL) BN_free(*d);

    return ret;
}

/**
 * Extracts to BIGNUM the signature s from an EVP generated signature sig (with length sig_len).
 * 
 * @param s The extracted signature.
 * @param sig The signature as a string.
 * @param sig_len The length of the signature.
 * 
 * @return 1 in case of success, and -1 in case of error.
 */
int rsa_sig_extract_bn(BIGNUM **s, unsigned char *sig, size_t sig_len) {
    int ret = 0;

    if(s == NULL || sig == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    if(*s == NULL) *s = BN_new();

    if( BN_bin2bn(sig, sig_len, *s) == NULL ) {
        ret = -1;
        goto sig_ext_err;
    }

    return 1;

sig_ext_err:
    if(*s != NULL) BN_free(*s);

    return ret;
}

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
int rsa_msg_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, BIGNUM *n) {
    int ret = 0, buf_len = 0;

    unsigned char *buf = NULL;
    unsigned char *dig = NULL;
    unsigned char *enc = NULL;

    unsigned int dig_len = 0;
    unsigned int enc_len = 0;

    EVP_MD_CTX *mdctx;
    const EVP_MD* md = NULL;

    if(m == NULL || msg == NULL || n == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    /* digest message */
    dig = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, dig, &dig_len) != 1 ) {
        printf("Failed to hash message\n");
        ret = -1;
        goto msg_ext_err;
    }

    /* digest encode */
    enc = (unsigned char *) OPENSSL_malloc(sizeof(sha256_der_encoding) + dig_len);
    memcpy(enc, sha256_der_encoding, sizeof(sha256_der_encoding));
    memcpy(enc + sizeof(sha256_der_encoding), dig, dig_len);
    enc_len = sizeof(sha256_der_encoding) + dig_len;

    /* padding */
    buf_len = BN_num_bytes(n);
    buf = OPENSSL_malloc(buf_len);
    RSA_padding_add_PKCS1_type_1(buf, buf_len, enc, enc_len);

    /* set BIGNUM */
    if(*m == NULL) *m = BN_new();
    if( BN_bin2bn(buf, buf_len, *m) == NULL ) {
        ret = -1;
        goto msg_ext_err;
    }

    return 1;

msg_ext_err:
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(*m != NULL) BN_free(*m);
    if(n != NULL) BN_free(n);
    if(buf != NULL) OPENSSL_free(buf);
    if(enc != NULL) OPENSSL_free(enc);

    return ret;
}

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
int rsa_msg_evp_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, EVP_PKEY *vkey) {
    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *n = NULL;

    if(vkey == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    n = BN_new();
    rsa = EVP_PKEY_get1_RSA(vkey);

    if(rsa == NULL) {
        printf("Unable to read RSA key\n");
        ret = -1;
        goto msg_evp_ext_err;
    }
    BN_copy(n, RSA_get0_n(rsa));

    ret = rsa_msg_extract_bn(m, msg, msg_len, n);

msg_evp_ext_err:
    if(n != NULL) BN_free(n);

    return ret;
}
