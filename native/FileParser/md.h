#ifndef MD_H
#define MD_H


/**
 * \brief     Supported message digests.
 *
 * \warning   MD2, MD4, MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
	MBEDTLS_MD_NONE,    /**< None. */
	MBEDTLS_MD_MD2,       /**< The MD2 message digest. */
	MBEDTLS_MD_MD4,       /**< The MD4 message digest. */
	MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
	MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
	MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
	MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
	MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */
	MBEDTLS_MD_SHA512,    /**< The SHA-512 message digest. */
	MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
	MBEDTLS_MD_PKCS1_MD2_RSA, /**< The md2WithRSAEncryption message digest. */
	MBEDTLS_MD_PKCS1_MD5_RSA, /**< The md5WithRSAEncryption message digest. */
	MBEDTLS_MD_PKCS1_SHA1_RSA, /**< The sha256WithRSAEncryption  message digest. */
	MBEDTLS_MD_PKCS1_SHA256_RSA, /**< The sha256WithRSAEncryption  message digest. */
	MBEDTLS_MD_PKCS1_SHA384_RSA, /**< The sha384WithRSAEncryption  message digest. */
	MBEDTLS_MD_PKCS1_SHA512_RSA, /**< The sha512WithRSAEncryption  message digest. */
	MBEDTLS_MD_PKCS1_SHA384_ECDSA,  /**< The sha394withECDSAEncryption  message digest. */
} mbedtls_md_type_t;

#endif // !MD_H
