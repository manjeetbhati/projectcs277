#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define MESSAGE "pajeets"
#define MESSAGE_LEN strlen(MESSAGE)

void handleErrors(void)
{
    printf("An error occurred\n");
    exit(1);
}



int sign(unsigned char *message, size_t message_len, EVP_PKEY *pkey, unsigned char **sig, size_t *sig_len)
{
    // Generate a SHA-256 hash of the message
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // Sign the hash
    EVP_MD_CTX *mdctx_sign;
    mdctx_sign = EVP_MD_CTX_new();
    EVP_SignInit(mdctx_sign, md);
    EVP_SignUpdate(mdctx_sign, md_value, md_len);
    *sig = malloc(EVP_PKEY_size(pkey));
    if (!EVP_SignFinal(mdctx_sign, *sig, sig_len, pkey)) {
        handleErrors();
    }
    EVP_MD_CTX_free(mdctx_sign);

    return 1;
}

int verify(unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, EVP_PKEY *pkey)
{
    // Generate a SHA-256 hash of the message
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    EVP_MD_CTX *mdctx_verify;
    mdctx_verify = EVP_MD_CTX_new();
    EVP_VerifyInit(mdctx_verify, md);
    EVP_VerifyUpdate(mdctx_verify, md_value, md_len);
    int verified;
    verified = EVP_VerifyFinal(mdctx_verify, sig, sig_len, pkey);
    EVP_MD_CTX_free(mdctx_verify);

    return verified;
}



int main(void)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();


    // Generate a key pair for signing
    EVP_PKEY *pkey;
    pkey = EVP_PKEY_new();
    RSA *rsa;
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);

    unsigned char *sig;
    size_t sig_len;
    if (!sign((unsigned char *)MESSAGE, MESSAGE_LEN, pkey, &sig, &sig_len)) {
        handleErrors();
    } 


    printf("Signature:\n");
    BIO_dump_fp(stdout, (const char *)sig, sig_len);

    int verified;
    verified = verify((unsigned char *)MESSAGE, MESSAGE_LEN, sig, sig_len, pkey);

    // Print the verification result
    if (verified == 1) {
        printf("Verification successful!\n");
    } else if (verified == 0) {
        printf("Verification failed!\n");
    } else {
        handleErrors();
    }

    // Clean up
    free(sig);
    EVP_PKEY_free(pkey);
    EVP_cleanup();

    return 0;
}

