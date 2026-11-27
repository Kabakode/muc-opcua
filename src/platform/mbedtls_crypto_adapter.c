/* src/platform/mbedtls_crypto_adapter.c */
#ifdef MUC_OPCUA_HAVE_MBEDTLS
#include "muc_opcua/config.h"
#include "muc_opcua/platform.h"
#include "muc_opcua/status.h"
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#ifdef MUC_OPCUA_CU_SECURITY_ECC
#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform_util.h>
#endif
#include <stdlib.h>
#include <string.h>

struct mbedtls_crypto_context {
    const opcua_byte_t *cert_der;
    size_t cert_len;
    const opcua_byte_t *key_der;
    size_t key_len;
    mbedtls_pk_context pk;
#ifdef MUC_OPCUA_CU_SECURITY_ECC
    /* Optional ECC signing identity (spec 059), provisioned by
       mu_mbedtls_crypto_adapter_set_ecc_identity. Only nistP256 is supported;
       mbedTLS 2.x has no Ed25519, so curve25519 is never provisioned here. */
    mbedtls_pk_context ecc_pk;
    const opcua_byte_t *ecc_cert_der;
    size_t ecc_cert_len;
    int ecc_provisioned;
#endif
};

/* mbedtls_md() has the same signature on mbedTLS 2.x and 3.x, unlike the
   sha256_ret/sha1_ret helpers that 3.x removed. */
static int m_hash(mbedtls_md_type_t type, const opcua_byte_t *data, size_t length, opcua_byte_t *out) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(type);
    return md_info ? mbedtls_md(md_info, data, length, out) : -1;
}

static opcua_statuscode_t m_sha256(void *context, const opcua_byte_t *data, size_t length, opcua_byte_t *digest) {
    (void)context;
    int ret = m_hash(MBEDTLS_MD_SHA256, data, length, digest);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_hmac_sha256(void *context, const opcua_byte_t *key, size_t key_length,
                                        const opcua_byte_t *data, size_t data_length, opcua_byte_t *mac) {
    (void)context;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    int ret = mbedtls_md_hmac(md_info, key, key_length, data, data_length, mac);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_aes256_cbc_encrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *iv,
                                               const opcua_byte_t *input, size_t length, opcua_byte_t *output) {
    (void)context;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    opcua_byte_t iv_copy[16];
    (void)memcpy(iv_copy, iv, 16);
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_aes256_cbc_decrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *iv,
                                               const opcua_byte_t *input, size_t length, opcua_byte_t *output) {
    (void)context;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_dec(&aes, key, 256);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    opcua_byte_t iv_copy[16];
    (void)memcpy(iv_copy, iv, 16);
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_aes128_cbc_encrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *iv,
                                               const opcua_byte_t *input, size_t length, opcua_byte_t *output) {
    (void)context;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, key, 128);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    opcua_byte_t iv_copy[16];
    (void)memcpy(iv_copy, iv, 16);
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_aes128_cbc_decrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *iv,
                                               const opcua_byte_t *input, size_t length, opcua_byte_t *output) {
    (void)context;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_dec(&aes, key, 128);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    opcua_byte_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_rsa_sha256_sign(void *context, const opcua_byte_t *data, size_t length,
                                            opcua_byte_t *signature, size_t *signature_length) {
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    opcua_byte_t hash[32];
    int ret = m_hash(MBEDTLS_MD_SHA256, data, length, hash);
    if (ret != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"sign", 4);
#if MBEDTLS_VERSION_MAJOR >= 3
    if (ret == 0) {
        /* mbedTLS 3.x added sig_size and requires f_rng for RSA blinding. */
        ret = mbedtls_pk_sign(&ctx->pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, *signature_length,
                              signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    }
#else
    ret = mbedtls_pk_sign(&ctx->pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, signature_length, NULL, NULL);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_rsa_sha256_verify(void *context, const opcua_byte_t *certificate, size_t certificate_length,
                                              const opcua_byte_t *data, size_t data_length,
                                              const opcua_byte_t *signature, size_t signature_length) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    opcua_byte_t hash[32];
    ret = m_hash(MBEDTLS_MD_SHA256, data, data_length, hash);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }

    ret = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, signature_length);
    mbedtls_x509_crt_free(&crt);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_SECURITYCHECKSFAILED;
}

static opcua_statuscode_t m_rsa_oaep_decrypt(void *context, const opcua_byte_t *input, size_t length,
                                             opcua_byte_t *output, size_t *output_length) {
    (void)length;
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (mbedtls_pk_get_type(&ctx->pk) != MBEDTLS_PK_RSA) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx->pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"oaep", 4);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return MU_STATUS_BAD_INTERNALERROR;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x removed the mode argument. */
    ret = mbedtls_rsa_rsaes_oaep_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, NULL, 0, output_length, input, output,
                                         *output_length);
#else
    ret = mbedtls_rsa_rsaes_oaep_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, NULL, 0,
                                         output_length, input, output, *output_length);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_SECURITYCHECKSFAILED;
}

static opcua_statuscode_t m_rsa_oaep_encrypt(void *context, const opcua_byte_t *certificate, size_t certificate_length,
                                             const opcua_byte_t *input, size_t length, opcua_byte_t *output,
                                             size_t *output_length) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(crt.pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"oaep", 4);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x removed the mode argument. */
    ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, NULL, 0, length, input, output);
#else
    ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, NULL, 0, length,
                                         input, output);
#endif
    *output_length = mbedtls_rsa_get_len(rsa);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&crt);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_rsa_pss_sha256_sign(void *context, const opcua_byte_t *data, size_t length,
                                                opcua_byte_t *signature, size_t *signature_length) {
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (mbedtls_pk_get_type(&ctx->pk) != MBEDTLS_PK_RSA) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx->pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    opcua_byte_t hash[32];
    int ret = m_hash(MBEDTLS_MD_SHA256, data, length, hash);
    if (ret != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"pss", 3);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return MU_STATUS_BAD_INTERNALERROR;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x removed the mode argument. */
    ret = mbedtls_rsa_rsassa_pss_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_MD_SHA256, sizeof(hash), hash,
                                      signature);
#else
    ret = mbedtls_rsa_rsassa_pss_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                      sizeof(hash), hash, signature);
#endif
    if (ret == 0) {
        *signature_length = mbedtls_rsa_get_len(rsa);
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

static opcua_statuscode_t m_rsa_pss_sha256_verify(void *context, const opcua_byte_t *certificate,
                                                  size_t certificate_length, const opcua_byte_t *data,
                                                  size_t data_length, const opcua_byte_t *signature,
                                                  size_t signature_length) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(crt.pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    opcua_byte_t hash[32];
    ret = m_hash(MBEDTLS_MD_SHA256, data, data_length, hash);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }

    if (signature_length != mbedtls_rsa_get_len(rsa)) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x: mode and RNG arguments removed (verify needs no RNG). */
    ret = mbedtls_rsa_rsassa_pss_verify(rsa, MBEDTLS_MD_SHA256, sizeof(hash), hash, signature);
#else
    ret = mbedtls_rsa_rsassa_pss_verify(rsa, mbedtls_ctr_drbg_random, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                        sizeof(hash), hash, signature);
#endif
    mbedtls_x509_crt_free(&crt);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_SECURITYCHECKSFAILED;
}

static opcua_statuscode_t m_rsa_oaep_sha256_decrypt(void *context, const opcua_byte_t *input, size_t length,
                                                    opcua_byte_t *output, size_t *output_length) {
    (void)length;
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (mbedtls_pk_get_type(&ctx->pk) != MBEDTLS_PK_RSA) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(ctx->pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"oaep", 4);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return MU_STATUS_BAD_INTERNALERROR;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x removed the mode argument. */
    ret = mbedtls_rsa_rsaes_oaep_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, NULL, 0, output_length, input, output,
                                         *output_length);
#else
    ret = mbedtls_rsa_rsaes_oaep_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, NULL, 0,
                                         output_length, input, output, *output_length);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_SECURITYCHECKSFAILED;
}

static opcua_statuscode_t m_rsa_oaep_sha256_encrypt(void *context, const opcua_byte_t *certificate,
                                                    size_t certificate_length, const opcua_byte_t *input, size_t length,
                                                    opcua_byte_t *output, size_t *output_length) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(crt.pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"oaep", 4);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_INTERNALERROR;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x removed the mode argument. */
    ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, NULL, 0, length, input, output);
#else
    ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, NULL, 0, length,
                                         input, output);
#endif
    if (ret == 0) {
        *output_length = mbedtls_rsa_get_len(rsa);
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&crt);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_SECURITYCHECKSFAILED;
}

static opcua_statuscode_t m_get_own_certificate(void *context, const opcua_byte_t **certificate, size_t *length) {
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (!ctx->cert_der) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    *certificate = ctx->cert_der;
    *length = ctx->cert_len;
    return MU_STATUS_GOOD;
}

static opcua_statuscode_t m_get_certificate_key_bits(void *context, const opcua_byte_t *certificate,
                                                     size_t certificate_length, size_t *bits) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
    *bits = mbedtls_pk_get_bitlen(&crt.pk);
    mbedtls_x509_crt_free(&crt);
    return MU_STATUS_GOOD;
}

static opcua_statuscode_t m_verify_certificate_validity(void *context, const opcua_byte_t *certificate,
                                                        size_t certificate_length) {
    (void)context;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_CERTIFICATEINVALID;
    }
    /* OPC-10000-4 §5.5: reject not-yet-valid or expired certificates. */
    int invalid = mbedtls_x509_time_is_future(&crt.valid_from) || mbedtls_x509_time_is_past(&crt.valid_to);
    mbedtls_x509_crt_free(&crt);
    return invalid ? MU_STATUS_BAD_CERTIFICATETIMEINVALID : MU_STATUS_GOOD;
}

static opcua_statuscode_t m_get_certificate_thumbprint(void *context, const opcua_byte_t *certificate,
                                                       size_t certificate_length, opcua_byte_t *thumbprint) {
    (void)context;
    int ret = m_hash(MBEDTLS_MD_SHA1, certificate, certificate_length, thumbprint);
    return (ret == 0) ? MU_STATUS_GOOD : MU_STATUS_BAD_INTERNALERROR;
}

#ifdef MUC_OPCUA_CU_SECURITY_ECC

/* mbedTLS 2.x has X25519 ECDH but no Ed25519 signatures, and the curve25519
   SecurityPolicy mandates Ed25519 — so a mbedTLS server can never complete a
   curve25519 handshake. Every curve25519 ECC op below therefore fails closed. */
#if defined(MU_STATUS_BAD_NOTSUPPORTED)
#define MU_ECC_CURVE25519_STATUS MU_STATUS_BAD_NOTSUPPORTED
#else
#define MU_ECC_CURVE25519_STATUS MU_STATUS_BAD_SECURITYPOLICYREJECTED
#endif

#define MU_P256_UNCOMPRESSED_LEN 65 /* 0x04 || X(32) || Y(32) */
#define MU_P256_COORD_LEN 32

_Static_assert(MU_ECC_KEYPAIR_CTX_SIZE >= MU_P256_COORD_LEN,
               "MU_ECC_KEYPAIR_CTX_SIZE must hold a 32-byte P-256 private scalar");

/* OPC UA carries ECDSA signatures as raw r||s (2 * MU_P256_COORD_LEN), while
   mbedtls_pk_sign/verify use DER. mbedTLS 3.x made mbedtls_ecp_keypair opaque,
   so the raw r/s conversion goes through DER instead of keypair members. */
#define MU_P256_DER_SIG_MAX 72 /* SEQUENCE { INTEGER r, INTEGER s } for P-256 */

static size_t m_der_encode_integer(opcua_byte_t *out, const opcua_byte_t *value, size_t len) {
    size_t pad = (len > 0 && (value[0] & 0x80) != 0) ? 1 : 0;
    size_t content = len + pad;
    out[0] = 0x02;
    out[1] = (opcua_byte_t)content; /* P-256 coordinates: always < 128 */
    if (pad) {
        out[2] = 0x00;
    }
    (void)memcpy(out + 2 + pad, value, len);
    return 2 + content;
}

static size_t m_der_encode_ecdsa_sig(opcua_byte_t *out, const opcua_byte_t *r, const opcua_byte_t *s,
                                     size_t coord_len) {
    opcua_byte_t body[2 * (2 + 1 + MU_P256_COORD_LEN)];
    size_t n = m_der_encode_integer(body, r, coord_len);
    n += m_der_encode_integer(body + n, s, coord_len);
    out[0] = 0x30;
    out[1] = (opcua_byte_t)n;
    (void)memcpy(out + 2, body, n);
    return 2 + n;
}

static int m_der_decode_ecdsa_sig(const opcua_byte_t *sig, size_t sig_len, opcua_byte_t *raw) {
    if (sig_len < 8 || sig[0] != 0x30 || sig[1] != sig_len - 2) {
        return -1;
    }
    size_t pos = 2;
    for (int i = 0; i < 2; i++) {
        if (pos + 2 > sig_len || sig[pos] != 0x02) {
            return -1;
        }
        size_t len = sig[pos + 1];
        pos += 2;
        if (len > MU_P256_COORD_LEN + 1 || pos + len > sig_len) {
            return -1;
        }
        const opcua_byte_t *v = sig + pos;
        if (len == MU_P256_COORD_LEN + 1 && v[0] == 0x00) {
            v++;
            len--;
        }
        if (len > MU_P256_COORD_LEN) {
            return -1;
        }
        opcua_byte_t *dst = raw + i * MU_P256_COORD_LEN + (MU_P256_COORD_LEN - len);
        (void)memset(dst, 0, MU_P256_COORD_LEN - len);
        (void)memcpy(dst, v, len);
        pos += len;
    }
    return (pos == sig_len) ? 0 : -1;
}

/* Seed a local CTR_DRBG from the entropy pool for the ECC primitives that need
   randomness (keygen, ECDSA nonce, ECDH blinding). Caller frees on success. */
static int m_ecc_seed_drbg(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *drbg) {
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(drbg);
    int ret = mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, (const unsigned char *)"muc-ecc", 7);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(drbg);
        mbedtls_entropy_free(entropy);
    }
    return ret;
}

static opcua_statuscode_t m_ecc_generate_ephemeral(void *context, mu_ecc_curve_t curve, opcua_byte_t *pubkey,
                                                   size_t *pubkey_length, opcua_byte_t *keypair_ctx) {
    (void)context;
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    if (!pubkey || !pubkey_length || !keypair_ctx || *pubkey_length < (size_t)(MU_P256_UNCOMPRESSED_LEN - 1)) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    if (m_ecc_seed_drbg(&entropy, &drbg) != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    opcua_statuscode_t rc = MU_STATUS_BAD_INTERNALERROR;
    opcua_byte_t enc[MU_P256_UNCOMPRESSED_LEN];
    size_t enc_len = 0;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_gen_keypair(&grp, &d, &q, mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &enc_len, enc, sizeof(enc)) == 0 &&
        enc_len == MU_P256_UNCOMPRESSED_LEN && enc[0] == 0x04 &&
        mbedtls_mpi_write_binary(&d, keypair_ctx, MU_P256_COORD_LEN) == 0) {
        (void)memcpy(pubkey, enc + 1, MU_P256_UNCOMPRESSED_LEN - 1); /* strip 0x04 prefix */
        *pubkey_length = MU_P256_UNCOMPRESSED_LEN - 1;
        rc = MU_STATUS_GOOD;
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return rc;
}

static opcua_statuscode_t m_ecc_ecdh_derive(void *context, mu_ecc_curve_t curve, const opcua_byte_t *keypair_ctx,
                                            const opcua_byte_t *peer_pubkey, size_t peer_pubkey_length,
                                            opcua_byte_t *shared, size_t *shared_length) {
    (void)context;
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    if (!keypair_ctx || !peer_pubkey || !shared || !shared_length ||
        peer_pubkey_length != (size_t)(MU_P256_UNCOMPRESSED_LEN - 1) || *shared_length < MU_P256_COORD_LEN) {
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    if (m_ecc_seed_drbg(&entropy, &drbg) != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_mpi z;
    mbedtls_ecp_point peer;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&peer);

    opcua_byte_t enc[MU_P256_UNCOMPRESSED_LEN];
    enc[0] = 0x04;
    (void)memcpy(enc + 1, peer_pubkey, MU_P256_UNCOMPRESSED_LEN - 1);

    opcua_statuscode_t rc = MU_STATUS_BAD_SECURITYCHECKSFAILED;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, keypair_ctx, MU_P256_COORD_LEN) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &peer, enc, sizeof(enc)) == 0 &&
        mbedtls_ecp_check_pubkey(&grp, &peer) == 0 &&
        mbedtls_ecdh_compute_shared(&grp, &z, &peer, &d, mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_mpi_write_binary(&z, shared, MU_P256_COORD_LEN) == 0) {
        *shared_length = MU_P256_COORD_LEN;
        rc = MU_STATUS_GOOD;
    }

    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return rc;
}

static void m_ecc_keypair_free(void *context, opcua_byte_t *keypair_ctx) {
    (void)context;
    if (keypair_ctx) {
        mbedtls_platform_zeroize(keypair_ctx, MU_ECC_KEYPAIR_CTX_SIZE);
    }
}

static opcua_statuscode_t m_ecc_sign(void *context, mu_ecc_curve_t curve, const opcua_byte_t *data, size_t length,
                                     opcua_byte_t *signature, size_t *signature_length) {
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (!ctx->ecc_provisioned || !signature || !signature_length || *signature_length < MU_ECC_SIGNATURE_LENGTH) {
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
    opcua_byte_t hash[32];
    if (m_hash(MBEDTLS_MD_SHA256, data, length, hash) != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    if (m_ecc_seed_drbg(&entropy, &drbg) != 0) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    opcua_byte_t der[MU_P256_DER_SIG_MAX];
    size_t der_len = 0;
#if MBEDTLS_VERSION_MAJOR >= 3
    int ret = mbedtls_pk_sign(&ctx->ecc_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), der, sizeof(der), &der_len,
                              mbedtls_ctr_drbg_random, &drbg);
#else
    int ret = mbedtls_pk_sign(&ctx->ecc_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), der, &der_len,
                              mbedtls_ctr_drbg_random, &drbg);
#endif
    opcua_statuscode_t rc = MU_STATUS_BAD_INTERNALERROR;
    if (ret == 0 && m_der_decode_ecdsa_sig(der, der_len, signature) == 0) {
        *signature_length = MU_ECC_SIGNATURE_LENGTH;
        rc = MU_STATUS_GOOD;
    }

    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return rc;
}

static opcua_statuscode_t m_ecc_verify(void *context, mu_ecc_curve_t curve, const opcua_byte_t *certificate,
                                       size_t certificate_length, const opcua_byte_t *data, size_t data_length,
                                       const opcua_byte_t *signature, size_t signature_length) {
    (void)context;
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    if (signature_length != MU_ECC_SIGNATURE_LENGTH) {
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, certificate, certificate_length) != 0) {
        mbedtls_x509_crt_free(&crt);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
    opcua_byte_t der[MU_P256_DER_SIG_MAX];
    size_t der_len = m_der_encode_ecdsa_sig(der, signature, signature + MU_P256_COORD_LEN, MU_P256_COORD_LEN);

    opcua_byte_t hash[32];
    opcua_statuscode_t rc = MU_STATUS_BAD_SECURITYCHECKSFAILED;
    if (m_hash(MBEDTLS_MD_SHA256, data, data_length, hash) == 0 &&
        mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), der, der_len) == 0) {
        rc = MU_STATUS_GOOD;
    }

    mbedtls_x509_crt_free(&crt);
    return rc;
}

static opcua_statuscode_t m_get_own_ecc_certificate(void *context, mu_ecc_curve_t curve,
                                                    const opcua_byte_t **certificate, size_t *length) {
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)context;
    if (!certificate || !length) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    if (!ctx->ecc_provisioned || !ctx->ecc_cert_der) {
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
    *certificate = ctx->ecc_cert_der;
    *length = ctx->ecc_cert_len;
    return MU_STATUS_GOOD;
}

static opcua_statuscode_t m_chacha20_poly1305_encrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *nonce,
                                                      const opcua_byte_t *aad, size_t aad_length,
                                                      const opcua_byte_t *input, size_t length, opcua_byte_t *output,
                                                      opcua_byte_t *tag) {
    (void)context;
    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    opcua_statuscode_t rc = MU_STATUS_BAD_INTERNALERROR;
    if (mbedtls_chachapoly_setkey(&cp, key) == 0 &&
        mbedtls_chachapoly_encrypt_and_tag(&cp, length, nonce, aad, aad_length, input, output, tag) == 0) {
        rc = MU_STATUS_GOOD;
    }
    mbedtls_chachapoly_free(&cp);
    return rc;
}

static opcua_statuscode_t m_chacha20_poly1305_decrypt(void *context, const opcua_byte_t *key, const opcua_byte_t *nonce,
                                                      const opcua_byte_t *aad, size_t aad_length,
                                                      const opcua_byte_t *input, size_t length, const opcua_byte_t *tag,
                                                      opcua_byte_t *output) {
    (void)context;
    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    /* Poly1305 tag mismatch fails closed inside auth_decrypt. */
    opcua_statuscode_t rc = MU_STATUS_BAD_SECURITYCHECKSFAILED;
    if (mbedtls_chachapoly_setkey(&cp, key) == 0 &&
        mbedtls_chachapoly_auth_decrypt(&cp, length, nonce, aad, aad_length, tag, input, output) == 0) {
        rc = MU_STATUS_GOOD;
    }
    mbedtls_chachapoly_free(&cp);
    return rc;
}

opcua_statuscode_t mu_mbedtls_crypto_adapter_set_ecc_identity(mu_crypto_adapter_t *adapter, mu_ecc_curve_t curve,
                                                              const opcua_byte_t *cert_der, size_t cert_len,
                                                              const opcua_byte_t *key_der, size_t key_len) {
    if (!adapter || !adapter->context || !cert_der || !key_der) {
        return MU_STATUS_BAD_INTERNALERROR;
    }
    /* mbedTLS 2.x lacks Ed25519, so the curve25519 policy cannot be served. */
    if (curve == MU_ECC_CURVE_25519) {
        return MU_ECC_CURVE25519_STATUS;
    }
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)adapter->context;
    if (ctx->ecc_provisioned) {
        mbedtls_pk_free(&ctx->ecc_pk);
        ctx->ecc_provisioned = 0;
    }
    mbedtls_pk_init(&ctx->ecc_pk);
#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x added f_rng/p_rng parameters (unused for plain DER keys). */
    int parse_ret = mbedtls_pk_parse_key(&ctx->ecc_pk, key_der, key_len, NULL, 0, NULL, NULL);
#else
    int parse_ret = mbedtls_pk_parse_key(&ctx->ecc_pk, key_der, key_len, NULL, 0);
#endif
    if (parse_ret != 0 || mbedtls_pk_get_type(&ctx->ecc_pk) != MBEDTLS_PK_ECKEY) {
        mbedtls_pk_free(&ctx->ecc_pk);
        return MU_STATUS_BAD_SECURITYCHECKSFAILED;
    }
    ctx->ecc_cert_der = cert_der;
    ctx->ecc_cert_len = cert_len;
    ctx->ecc_provisioned = 1;
    return MU_STATUS_GOOD;
}

#endif /* MUC_OPCUA_CU_SECURITY_ECC */

opcua_statuscode_t mu_mbedtls_crypto_adapter_init(mu_crypto_adapter_t *adapter, const opcua_byte_t *cert_der,
                                                  size_t cert_len, const opcua_byte_t *key_der, size_t key_len) {
    if (!adapter) {
        return MU_STATUS_BAD_INTERNALERROR;
    }

    /* Mbed TLS crypto adapter (host/RTOS platforms with a heap); not gated by
       MUC_OPCUA_ALLOW_HEAP, which governs the freestanding no-heap core. */
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return MU_STATUS_BAD_OUTOFMEMORY;
    }

    ctx->cert_der = cert_der;
    ctx->cert_len = cert_len;
    ctx->key_der = key_der;
    ctx->key_len = key_len;

    mbedtls_pk_init(&ctx->pk);
#if MBEDTLS_VERSION_MAJOR >= 3
    /* mbedTLS 3.x added f_rng/p_rng parameters (unused for plain DER keys). */
    int ret = mbedtls_pk_parse_key(&ctx->pk, key_der, key_len, NULL, 0, NULL, NULL);
#else
    int ret = mbedtls_pk_parse_key(&ctx->pk, key_der, key_len, NULL, 0);
#endif
    if (ret != 0) {
        mbedtls_pk_free(&ctx->pk);
        free(ctx);
        return MU_STATUS_BAD_INTERNALERROR;
    }

    adapter->context = ctx;
    adapter->sha256 = m_sha256;
    adapter->hmac_sha256 = m_hmac_sha256;
    adapter->aes256_cbc_encrypt = m_aes256_cbc_encrypt;
    adapter->aes256_cbc_decrypt = m_aes256_cbc_decrypt;
    adapter->aes128_cbc_encrypt = m_aes128_cbc_encrypt;
    adapter->aes128_cbc_decrypt = m_aes128_cbc_decrypt;
    adapter->cipher_ctx_init = NULL;
    adapter->aes256_cbc_encrypt_ctx = NULL;
    adapter->aes256_cbc_decrypt_ctx = NULL;
    adapter->cipher_ctx_free = NULL;
    adapter->rsa_sha256_sign = m_rsa_sha256_sign;
    adapter->rsa_sha256_verify = m_rsa_sha256_verify;
    adapter->rsa_oaep_decrypt = m_rsa_oaep_decrypt;
    adapter->rsa_oaep_encrypt = m_rsa_oaep_encrypt;
    adapter->rsa_pss_sha256_sign = m_rsa_pss_sha256_sign;
    adapter->rsa_pss_sha256_verify = m_rsa_pss_sha256_verify;
    adapter->rsa_oaep_sha256_decrypt = m_rsa_oaep_sha256_decrypt;
    adapter->rsa_oaep_sha256_encrypt = m_rsa_oaep_sha256_encrypt;
    adapter->get_own_certificate = m_get_own_certificate;
    adapter->get_certificate_key_bits = m_get_certificate_key_bits;
    adapter->get_certificate_thumbprint = m_get_certificate_thumbprint;
    adapter->verify_certificate_validity = m_verify_certificate_validity;
#ifdef MUC_OPCUA_CU_SECURITY_ECC
    /* ECC identity is provisioned separately via
       mu_mbedtls_crypto_adapter_set_ecc_identity; the vtable slots are wired
       unconditionally (nistP256 works; curve25519 fails closed — no Ed25519). */
    ctx->ecc_provisioned = 0;
    adapter->ecc_generate_ephemeral = m_ecc_generate_ephemeral;
    adapter->ecc_ecdh_derive = m_ecc_ecdh_derive;
    adapter->ecc_keypair_free = m_ecc_keypair_free;
    adapter->ecc_sign = m_ecc_sign;
    adapter->ecc_verify = m_ecc_verify;
    adapter->get_own_ecc_certificate = m_get_own_ecc_certificate;
    adapter->chacha20_poly1305_encrypt = m_chacha20_poly1305_encrypt;
    adapter->chacha20_poly1305_decrypt = m_chacha20_poly1305_decrypt;
#endif

    return MU_STATUS_GOOD;
}

void mu_mbedtls_crypto_adapter_cleanup(mu_crypto_adapter_t *adapter) {
    if (!adapter || !adapter->context) {
        return;
    }
    struct mbedtls_crypto_context *ctx = (struct mbedtls_crypto_context *)adapter->context;
    mbedtls_pk_free(&ctx->pk);
#ifdef MUC_OPCUA_CU_SECURITY_ECC
    if (ctx->ecc_provisioned) {
        mbedtls_pk_free(&ctx->ecc_pk);
    }
#endif
    free(ctx);
    adapter->context = NULL;
}
#else
typedef int mu_mbedtls_dummy;
#endif
