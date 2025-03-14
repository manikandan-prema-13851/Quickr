#include "oid.h"
#include <stdio.h>
#include <Windows.h>



/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s)      s, MBEDTLS_OID_SIZE(s)


#define OID_SAFE_SNPRINTF                               \
    do {                                                \
        if( ret < 0 || (size_t) ret >= n )              \
            return( MBEDTLS_ERR_OID_BUF_TOO_SMALL );    \
                                                        \
        n -= (size_t) ret;                              \
        p += (size_t) ret;                              \
    } while( 0 )




 /*
  * Macro to generate an internal function for oid_XXX_from_asn1() (used by
  * the other functions)
  */
#define FN_OID_TYPED_FROM_ASN1( TYPE_T, NAME, LIST )                    \
    static const TYPE_T * oid_ ## NAME ## _from_asn1(                   \
                                      const mbedtls_asn1_buf *oid )     \
    {                                                                   \
        const TYPE_T *p = (LIST);                                       \
        const mbedtls_oid_descriptor_t *cur =                           \
            (const mbedtls_oid_descriptor_t *) p;                       \
        if( p == NULL || oid == NULL ) return( NULL );                  \
        while( cur->asn1 != NULL ) {                                    \
            if( cur->asn1_len == oid->len &&                            \
                memcmp( cur->asn1, oid->p, oid->len ) == 0 ) {          \
                return( p );                                            \
            }                                                           \
            p++;                                                        \
            cur = (const mbedtls_oid_descriptor_t *) p;                 \
        }                                                               \
        return( NULL );                                                 \
    }




  /*
   * Macro to generate a function for retrieving a single attribute from an
   * mbedtls_oid_descriptor_t wrapper.
   */
#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const mbedtls_asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( MBEDTLS_ERR_OID_NOT_FOUND );             \
    *ATTR1 = data->ATTR1;                                               \
    return( 0 );                                                        \
}



   /*
	* Macro to generate a function for retrieving the OID based on a single
	* attribute from a mbedtls_oid_descriptor_t wrapper.
	*/
#define FN_OID_GET_OID_BY_ATTR1(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1)   \
int FN_NAME( ATTR1_TYPE ATTR1, const char **oid, size_t *olen )             \
{                                                                           \
    const TYPE_T *cur = (LIST);                                             \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == (ATTR1) ) {                                       \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( MBEDTLS_ERR_OID_NOT_FOUND );                                    \
}



int (*mbedtls_snprintf)(char* s, size_t n,
	const char* format,
	...) = snprintf;




/* Return the x.y.z.... style numeric string for the given OID */
int mbedtls_oid_get_numeric_string(char* buf, size_t size,
	const mbedtls_asn1_buf* oid)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t i, n;
	unsigned int value;
	char* p;

	p = buf;
	n = size;

	/* First byte contains first two dots */
	if (oid->len > 0)
	{
		ret = mbedtls_snprintf(p, n, "%d.%d", oid->p[0] / 40, oid->p[0] % 40);
		OID_SAFE_SNPRINTF;
	}

	value = 0;
	for (i = 1; i < oid->len; i++)
	{
		/* Prevent overflow in value. */
		if (((value << 7) >> 7) != value)
			return(MBEDTLS_ERR_OID_BUF_TOO_SMALL);

		value <<= 7;
		value += oid->p[i] & 0x7F;

		if (!(oid->p[i] & 0x80))
		{
			/* Last byte */
			ret = mbedtls_snprintf(p, n, ".%u", value);
			OID_SAFE_SNPRINTF;
			value = 0;
		}
	}

	return((int)(size - n));
}


/*
 * For digestAlgorithm
 */
typedef struct {
	mbedtls_oid_descriptor_t    descriptor;
	mbedtls_md_type_t           md_alg;
} oid_md_alg_t;

static const oid_md_alg_t oid_md_alg[] =
{
#if defined(MBEDTLS_MD2_C)
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_MD2),       "id-md2",       "MD2" },
		MBEDTLS_MD_MD2,
	},
#endif /* MBEDTLS_MD2_C */
#if defined(MBEDTLS_MD4_C)
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_MD4),       "id-md4",       "MD4" },
		MBEDTLS_MD_MD4,
	},
#endif /* MBEDTLS_MD4_C */
#if defined(MBEDTLS_MD5_C)
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_MD5),       "id-md5",       "MD5" },
		MBEDTLS_MD_MD5,
	},
#endif /* MBEDTLS_MD5_C */
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA1),      "id-sha1",      "SHA-1" },
		MBEDTLS_MD_SHA1,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA224),    "id-sha224",    "SHA-224" },
		MBEDTLS_MD_SHA224,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA256),    "id-sha256",    "SHA-256" },
		MBEDTLS_MD_SHA256,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA384),    "id-sha384",    "SHA-384" },
		MBEDTLS_MD_SHA384,
	},
		{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA512),    "id-sha512",    "SHA-512" },
		MBEDTLS_MD_SHA512,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_MD2),         "md2WithRSAEncryption  ", "MD2-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_MD2_RSA,
	},

	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_MD5),         "md5WithRSAEncryption  ", "MD5-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_MD5_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_SHA1),         "sha1WithRSAEncryption ", "SHA1-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA1_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_SHA1_OIW),         "sha1WithRSAEncryption ", "SHA1-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA1_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_SHA256),         "sha256WithRSAEncryption", "SHA256-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA256_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_SHA384),         "sha384WithRSAEncryption", "SHA384-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA384_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_PKCS1_SHA512),         "sha512WithRSAEncryption", "SHA512-RSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA512_RSA,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_ECDSA_SHA384),         "sha384WithECDSAEncryption", "SHA384-ECDSA-PKCS1"  },
		MBEDTLS_MD_PKCS1_SHA384_ECDSA,
	},
#if defined(MBEDTLS_SHA512_C)
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_SHA512),    "id-sha512",    "SHA-512" },
		MBEDTLS_MD_SHA512,
	},
#endif /* MBEDTLS_SHA512_C */
#if defined(MBEDTLS_RIPEMD160_C)
	{
		{ ADD_LEN(MBEDTLS_OID_DIGEST_ALG_RIPEMD160),       "id-ripemd160",       "RIPEMD-160" },
		MBEDTLS_MD_RIPEMD160,
	},
#endif /* MBEDTLS_RIPEMD160_C */
	{
		{ NULL, 0, NULL, NULL },
		MBEDTLS_MD_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_md_alg_t, md_alg, oid_md_alg)
FN_OID_GET_ATTR1(mbedtls_oid_get_md_alg, oid_md_alg_t, md_alg, mbedtls_md_type_t, md_alg)
FN_OID_GET_OID_BY_ATTR1(mbedtls_oid_get_oid_by_md, oid_md_alg_t, oid_md_alg, mbedtls_md_type_t, md_alg)

/*
 * For HMAC digestAlgorithm
 */
	typedef struct {
	mbedtls_oid_descriptor_t    descriptor;
	mbedtls_md_type_t           md_hmac;
} oid_md_hmac_t;

static const oid_md_hmac_t oid_md_hmac[] =
{
#if defined(MBEDTLS_SHA1_C)
	{
		{ ADD_LEN(MBEDTLS_OID_HMAC_SHA1),      "hmacSHA1",      "HMAC-SHA-1" },
		MBEDTLS_MD_SHA1,
	},
#endif /* MBEDTLS_SHA1_C */
#if defined(MBEDTLS_SHA256_C)
	{
		{ ADD_LEN(MBEDTLS_OID_HMAC_SHA224),    "hmacSHA224",    "HMAC-SHA-224" },
		MBEDTLS_MD_SHA224,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_HMAC_SHA256),    "hmacSHA256",    "HMAC-SHA-256" },
		MBEDTLS_MD_SHA256,
	},
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
	{
		{ ADD_LEN(MBEDTLS_OID_HMAC_SHA384),    "hmacSHA384",    "HMAC-SHA-384" },
		MBEDTLS_MD_SHA384,
	},
	{
		{ ADD_LEN(MBEDTLS_OID_HMAC_SHA512),    "hmacSHA512",    "HMAC-SHA-512" },
		MBEDTLS_MD_SHA512,
	},
#endif /* MBEDTLS_SHA512_C */
	{
		{ NULL, 0, NULL, NULL },
		MBEDTLS_MD_NONE,
	},
};

FN_OID_TYPED_FROM_ASN1(oid_md_hmac_t, md_hmac, oid_md_hmac)
FN_OID_GET_ATTR1(mbedtls_oid_get_md_hmac, oid_md_hmac_t, md_hmac, mbedtls_md_type_t, md_hmac)


char* createStringInHeap(char* name, size_t size) {
	char* nameInHeap = (char*)calloc((size + 1), sizeof(char));
	if (nameInHeap) {
		//printf("%s -- %d\n", name, size);
		memcpy(nameInHeap, name, size);
		nameInHeap[size] = '\0';
		return nameInHeap;
	}
	return nameInHeap;
}


void fill_oid_name(mbedtls_md_type_t alg, char** name) {
	switch (alg)
	{
	case MBEDTLS_MD_PKCS1_MD2_RSA:
		*name = createStringInHeap("MD2withRSA", strlen("MD2withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_MD5_RSA:
		*name = createStringInHeap("MD5withRSA", strlen("MD5withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_SHA1_RSA:
		*name = createStringInHeap("SHA1withRSA", strlen("SHA1withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_SHA256_RSA:
		*name = createStringInHeap("SHA256withRSA", strlen("SHA256withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_SHA384_RSA:
		*name = createStringInHeap("SHA384withRSA", strlen("SHA384withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_SHA512_RSA:
		*name = createStringInHeap("SHA512withRSA", strlen("SHA512withRSA"));
		break;
	case MBEDTLS_MD_PKCS1_SHA384_ECDSA:
		*name = createStringInHeap("SHA384withECDSA", strlen("SHA384withECDSA"));
		break;
	case MBEDTLS_MD_SHA512:
		*name = createStringInHeap("SHA512", strlen("SHA512"));
		break;
	case MBEDTLS_MD_MD5:
		*name = createStringInHeap("MD5", strlen("MD5"));
		break;
	case MBEDTLS_MD_SHA1:
		*name = createStringInHeap("SHA1", strlen("SHA1"));
		break;
	case MBEDTLS_MD_SHA224:
		*name = createStringInHeap("SHA224", strlen("SHA224"));
		break;
	case MBEDTLS_MD_SHA256:
		*name = createStringInHeap("SHA256", strlen("SHA256"));
		break;
	case MBEDTLS_MD_SHA384:
		*name = createStringInHeap("SHA384", strlen("SHA384"));
		break;
	default:
		*name = createStringInHeap("n/a", strlen("n/a"));
		break;
	}

}



int compareOID(char* target, int targetLen, char* oidToCheck, int oidToCheckLen)
{
	oidToCheckLen = oidToCheckLen - 1;
	if (targetLen == oidToCheckLen) {
		int i = 0;
		for (; i <= oidToCheckLen; i++) {
			if (target[i] != oidToCheck[i]) break;
		}
		if (i != oidToCheckLen) {
			return -1;
		}
		else {
			return 0;
		}
	}
	else {
		return -1;
	}

}