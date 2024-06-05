#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "rsa_sig_proof.h"
#include "rsa_sig_proof_util.h"

#include "string.h"
#include "cJSON.h"

/**
 * Allocates space to a new proof of ownership of an RSA signature with proof_len components.
 * 
 * @param proof_len The number of components in the proof.
 * 
 * @return A pointer to the space allocated to the proof.
 */
rsa_sig_proof_t *rsa_sig_proof_new(int proof_len) {
    int i;
    rsa_sig_proof_t *proof = NULL;

    proof = (rsa_sig_proof_t *) OPENSSL_malloc(sizeof(rsa_sig_proof_t));
    proof->p = (BIGNUM **) OPENSSL_malloc(proof_len*sizeof(BIGNUM *));
    proof->c = (BIGNUM **) OPENSSL_malloc(proof_len*sizeof(BIGNUM *));
    proof->len = proof_len;

    for(i = 0; i < proof_len; i++) {
        proof->p[i] = BN_secure_new();
        proof->c[i] = BN_secure_new();
    }

    return proof;
}

/**
 * Deallocates the space allocated to a proof of an RSA signature.
 * 
 * @param proof The proof to be deallocated. It is returned as NULL.
 */
void rsa_sig_proof_free(rsa_sig_proof_t *proof) {
    int i;

    if(proof == NULL) return;

    for(i = 0; i < proof->len; i++) {
        if(proof->p[i] != NULL) BN_free(proof->p[i]);
        if(proof->c[i] != NULL) BN_free(proof->c[i]);
    }

    OPENSSL_free(proof);
    proof = NULL;
}


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
rsa_sig_proof_t *rsa_sig_proof_prove(int sec_len, int proof_len, const BIGNUM *s, const BIGNUM *e,
                                     const BIGNUM *n) {
    int i;
    rsa_sig_proof_t *proof;

    BN_CTX *bnctx = NULL;
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    unsigned char *c_bytes = NULL;
    unsigned char *b = NULL;
    unsigned int b_len = 0;

    proof = rsa_sig_proof_new(proof_len);

    bnctx = BN_CTX_secure_new();
    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    c_bytes = (unsigned char *) OPENSSL_malloc(sec_len);
    b = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));

    for(i = 0; i < proof_len; i++) {
        //r_i =R Zn
        if( BN_rand_range(proof->p[i], n) != 1 ) {
            printf("Failed to generate %d-th random\n", i);
            rsa_sig_proof_free(proof);
            goto proof_err;
        }

        //c_i = r_i^e : commitments
        BN_mod_exp(proof->c[i], proof->p[i], e, n, bnctx);
    }

    //b = hash(c_i, forall i)
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ) {
        printf("ERROR\n");
        rsa_sig_proof_free(proof);
        goto proof_err;
    }
    for(i = 0; i < proof_len; i++) {
        BN_bn2bin(proof->c[i], c_bytes);
        if( EVP_DigestUpdate(mdctx, c_bytes, BN_num_bytes(proof->c[i])) != 1 ) {
            printf("ERROR\n");
            rsa_sig_proof_free(proof);
            goto proof_err;
        }
    }
    if( EVP_DigestFinal_ex(mdctx, b, &b_len) != 1 ) {
        printf("ERROR\n");
        rsa_sig_proof_free(proof);
        goto proof_err;
    }

    for(i = 0; i < proof_len; i++) {
        if((b[i/8] >> (7-i%8)) &0x01) { //==1
            //open p_i = z_i = S r_i
            BN_mod_mul(proof->p[i], s, proof->p[i], n, bnctx);
        }
        else { //==0
            //open p_i = r_i (NOP)
        }
    }

proof_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(c_bytes != NULL) OPENSSL_free(c_bytes);
    if(b != NULL) OPENSSL_free(b);

    return proof;
}

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
int rsa_sig_proof_ver(rsa_sig_proof_t *proof, const BIGNUM *m, const BIGNUM *e, const BIGNUM *n) {
    int i, ret = -1;

    BN_CTX *bnctx = NULL;
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    unsigned char *c_bytes = NULL;
    unsigned char *b = NULL;
    unsigned int b_len = 0;

    BIGNUM *f1, *f2;

    bnctx = BN_CTX_secure_new();
    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    c_bytes = (unsigned char *) OPENSSL_malloc(BN_num_bytes(n));
    b = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));

    f1 = BN_new();
    f2 = BN_new();

    //b = hash(c_i, forall i)
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ) {
        printf("ERROR\n");
        goto ver_err;
    }
    for(i = 0; i < proof->len; i++) {
        BN_bn2bin(proof->c[i], c_bytes);
        if( EVP_DigestUpdate(mdctx, c_bytes, BN_num_bytes(proof->c[i])) != 1 ) {
            printf("ERROR\n");
            goto ver_err;
        }
    }
    if( EVP_DigestFinal_ex(mdctx, b, &b_len) != 1 ) {
        printf("ERROR\n");
        goto ver_err;
    }

    for(i = 0; i < proof->len; i++) {
        BN_mod_exp(f1, proof->p[i], e, n, bnctx);
        if((b[i/8] >> (7-i%8)) &0x01) { //==1
            //assert p_i^e == M c_i
            BN_mod_mul(f2, m, proof->c[i], n, bnctx);
            if( BN_cmp(f1, f2) != 0 ) {
                ret = 0;
                goto ver_err;
            }
        }
        else { //==0
            BN_copy(f2, proof->c[i]);
            //assert p_i^e == c_i
            if( BN_cmp(f1, f2) != 0 ) {
                ret = 0;
                goto ver_err;
            }
        }
    }

    ret = 1;

ver_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(c_bytes != NULL) OPENSSL_free(c_bytes);
    if(b != NULL) OPENSSL_free(b);
    if(f1 != NULL) BN_free(f1);
    if(f2 != NULL) BN_free(f2);

    return ret;
}


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
rsa_sig_proof_t *rsa_evp_sig_proof_prove(int sec_len, int proof_len, unsigned char *sig,
                                         unsigned int sig_len, EVP_PKEY *vkey) {
    BIGNUM *n = NULL, *e = NULL, *s = NULL;

    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_sig_extract_bn(&s, sig, (size_t) sig_len) != 1 ) {
        return NULL;
    }

    return rsa_sig_proof_prove(sec_len, proof_len, s, e, n);
}

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
int rsa_evp_sig_proof_ver(rsa_sig_proof_t *proof, unsigned char *msg, unsigned int msg_len,
                          EVP_PKEY *vkey) {
    BIGNUM *n = NULL, *e = NULL, *m = NULL;

    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_msg_evp_extract_bn(&m, msg, msg_len, vkey) != 1 ) {
        return -1;
    }

    return rsa_sig_proof_ver(proof, m, e, n);
}

/**
 * Make a copy from a proof of ownership of an RSA signature.
 * 
 * @param proof_len The length of the proof.
 * @param proofsrc The proof to be copied.
 * 
 * @return A new proof represented as (rsa_sig_proof_t).
 */
rsa_sig_proof_t *rsa_sig_proof_copy(int proof_len, rsa_sig_proof_t *proofsrc) {
    int i;
    rsa_sig_proof_t *proofdest;

    proofdest = rsa_sig_proof_new(proof_len);

    for(i = 0; i < proof_len; i++) {

        BN_copy(proofdest->p[i], proofsrc->p[i]);
		BN_copy(proofdest->c[i], proofsrc->c[i]);

    }

    return proofdest;
}

/**
 * 
 * 
 * @param proof_len The length of the proof.
 * @param proof The proof to be copied.
 * 
 * @return A new proof represented as (rsa_sig_proof_t).
 */
char* rsa_sig_proof2hex(int proof_len, rsa_sig_proof_t *proof) {

    int i;
    char *tmpP, *tmpC;
    char *output;
    cJSON *root, *proofp, *proofc, *eachproof;
    char number[32] ={0};

    /* create root node and array */
    root = cJSON_CreateObject();
    proofp = cJSON_CreateArray();
    proofc = cJSON_CreateArray();


   /* add proof array to root */
    cJSON_AddItemToObject(root, "proofp", proofp);    
    cJSON_AddItemToObject(root, "proofc", proofc);   

    for(i = 0; i < proof_len; i++) {

        tmpP = BN_bn2hex(proof->p[i]);
        tmpC = BN_bn2hex(proof->c[i]);

        sprintf(number, "%d", i);

        /* add proof.p item to array proofp */
        cJSON_AddItemToArray(proofp, eachproof = cJSON_CreateObject());
        cJSON_AddItemToObject(eachproof, number, cJSON_CreateString(tmpP));
        /* add proof.c item to array proofc */
        cJSON_AddItemToArray(proofc, eachproof = cJSON_CreateObject());
        cJSON_AddItemToObject(eachproof, number, cJSON_CreateString(tmpC));

    }

    output = cJSON_Print(root);
    // printf("%s\n", output);
    cJSON_Delete(root);
    
    return output;
}

/**
 * 
 * 
 * @param proof_len The length of the proof.
 * @param proof The proof to be copied.
 * 
 * @return A new proof represented as (rsa_sig_proof_t).
 */
rsa_sig_proof_t *rsa_sig_hex2proof(int proof_len, char *hexproof) {

    int i;
    // cJSON *iterator = NULL;
    cJSON *p_array = NULL;
    cJSON *c_array = NULL;
    cJSON *itemP = NULL;
    cJSON *itemC = NULL;
    cJSON *tmpP = NULL;
    cJSON *tmpC = NULL;
    // char *P = NULL;
    char number[32] ={0};
    rsa_sig_proof_t *proof;

    proof = rsa_sig_proof_new(proof_len);
    proof->len = proof_len;

    cJSON *root = cJSON_Parse(hexproof);
    if (!cJSON_IsObject(root)) {
        printf("hexproof is not object");
	// 	return EXIT_FAILURE;
	}

    p_array = cJSON_GetObjectItem(root, "proofp");
	if (!cJSON_IsArray(p_array)) {
        printf("proofp is not array");
	}

    c_array = cJSON_GetObjectItem(root, "proofc");
	if (!cJSON_IsArray(c_array)) {
        printf("proofc is not array");
	}    

    for(i = 0; i < proof_len; i++) {

        sprintf(number, "%d", i);
        tmpP = cJSON_GetArrayItem(p_array, i);
        itemP = cJSON_GetObjectItem(tmpP, number);
        // printf("P value: %s\n", itemP->valuestring);
        if ( BN_hex2bn(&proof->p[i], itemP->valuestring) == 0 ) {
            printf("Error converting tmpP to proof.p");
        }

        tmpC = cJSON_GetArrayItem(c_array, i);
        itemC = cJSON_GetObjectItem(tmpC, number);
        // printf("C value: %s\n", itemC->valuestring);
        if ( BN_hex2bn(&proof->c[i], itemC->valuestring) == 0 ) {
            printf("Error converting tmpP to proof.p");
        }
    }

    cJSON_Delete(root);
    return proof;
}
