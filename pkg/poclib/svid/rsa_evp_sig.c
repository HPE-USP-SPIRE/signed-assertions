#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
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
int rsa_evp_keygen(EVP_PKEY **skey, EVP_PKEY **vkey, unsigned int sec_len) {
    int ret = 0;
    RSA* rsa = NULL;
    BIGNUM *bne = NULL;

    if(skey == NULL || vkey == NULL) {
        printf("Uninitialised key pointers\n");
        return -1;
    }

    //potentially, we could reuse pointers
    if(*skey != NULL) EVP_PKEY_free(*skey);
    if(*vkey != NULL) EVP_PKEY_free(*vkey);

    *skey = EVP_PKEY_new();
    *vkey = EVP_PKEY_new();

    bne = BN_secure_new();
    rsa = RSA_new();

    if( BN_set_word(bne, RSA_F4) != 1 ||
        RSA_generate_key_ex(rsa, sec_len, bne, NULL) != 1 ) {
        printf("Error generating keys\n");
        ret = -1;
        goto kg_err;
    }

    if( *skey == NULL || *vkey == NULL || rsa == NULL ||
        EVP_PKEY_assign_RSA(*skey, RSAPrivateKey_dup(rsa)) != 1 ||
        EVP_PKEY_assign_RSA(*vkey, RSAPublicKey_dup(rsa)) != 1 ) {
        printf("Error initializing keys\n");
        ret = -1;
        goto kg_err;
    }

    return 1;

kg_err:
    if(bne != NULL) BN_free(bne);
    if(*vkey != NULL) EVP_PKEY_free(*vkey);
    if(*skey != NULL) EVP_PKEY_free(*skey);
    if(rsa != NULL) RSA_free(rsa);

    return ret;
}

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
                 EVP_PKEY *skey) {
    int ret = 0;

    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    if(sig == NULL || sig_len == NULL || msg == NULL) {
        printf("Uninitialised signature pointers\n");
        return -1;
    }

    if(skey == NULL) {
        printf("Uninitialised signing key\n");
        return -1;
    }

    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestSignInit(mdctx, NULL, md, NULL, skey) != 1 ||
        EVP_DigestSignUpdate(mdctx, msg, msg_len) != 1 ||
        EVP_DigestSignFinal(mdctx, NULL, sig_len) != 1 ) {
        printf("Error computing signing hash\n");
        ret = -1;
        goto sig_err;
    }

    if(*sig == NULL) {
        *sig = (unsigned char *) OPENSSL_malloc(*sig_len);
    }

    if( EVP_DigestSignFinal(mdctx, *sig, sig_len) != 1 ) {
        printf("Error generating signature\n");
        OPENSSL_free(*sig);
        *sig_len = -1;
        ret = -1;
        goto sig_err;
    }

    ret = 1;

sig_err:
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);

    return ret;
}

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
                   EVP_PKEY *vkey) {
    int ret = 0;

    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    if(sig == NULL || msg == NULL) {
        printf("Uninitialised verification pointers\n");
        return -1;
    }

    if(vkey == NULL) {
        printf("Uninitialised signing key\n");
        return -1;
    }

    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestVerifyInit(mdctx, NULL, md, NULL, vkey) != 1 ||
        EVP_DigestVerifyUpdate(mdctx, msg, msg_len) != 1 ) {
        printf("Error computing verification hash\n");
        ret = -1;
        goto ver_err;
    }

    if( EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1 ){
        ret = 0;
        goto ver_err;
    }

    ret = 1;

ver_err:
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);

    return ret;
}
