


#ifndef _LINUX_OID_REGISTRY_H
#define _LINUX_OID_REGISTRY_H
#include <Windows.h>

/*
 * OIDs are turned into these values if possible, or OID__NR if not held here.
 *
 * NOTE!  Do not mess with the format of each line as this is read by
 *	  build_OID_registry.pl to generate the data for look_up_OID().
 */
enum OID {
	OID_id_dsa_with_sha1,		/* 1.2.840.10030.4.3 */
	OID_id_dsa,			/* 1.2.840.10040.4.1 */
	OID_id_ecdsa_with_sha1,		/* 1.2.840.10045.4.1 */
	OID_id_ecPublicKey,		/* 1.2.840.10045.2.1 */

	/* PKCS#1 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)} */
	OID_rsaEncryption,		/* 1.2.840.113549.1.1.1 */
	OID_md2WithRSAEncryption,	/* 1.2.840.113549.1.1.2 */
	OID_md3WithRSAEncryption,	/* 1.2.840.113549.1.1.3 */
	OID_md4WithRSAEncryption,	/* 1.2.840.113549.1.1.4 */
	OID_sha1WithRSAEncryption,	/* 1.2.840.113549.1.1.5 */
	OID_sha256WithRSAEncryption,	/* 1.2.840.113549.1.1.11 */
	OID_sha384WithRSAEncryption,	/* 1.2.840.113549.1.1.12 */
	OID_sha512WithRSAEncryption,	/* 1.2.840.113549.1.1.13 */
	OID_sha224WithRSAEncryption,	/* 1.2.840.113549.1.1.14 */
	/* PKCS#7 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7)} */
	OID_data,			/* 1.2.840.113549.1.7.1 */
	OID_signed_data,		/* 1.2.840.113549.1.7.2 */
	/* PKCS#9 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)} */
	OID_email_address,		/* 1.2.840.113549.1.9.1 */
	OID_contentType,		/* 1.2.840.113549.1.9.3 */
	OID_messageDigest,		/* 1.2.840.113549.1.9.4 */
	OID_signingTime,		/* 1.2.840.113549.1.9.5 */
	OID_smimeCapabilites,		/* 1.2.840.113549.1.9.15 */
	OID_smimeAuthenticatedAttrs,	/* 1.2.840.113549.1.9.16.2.11 */

	/* {iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2)} */
	OID_md2,			/* 1.2.840.113549.2.2 */
	OID_md4,			/* 1.2.840.113549.2.4 */
	OID_md5,			/* 1.2.840.113549.2.5 */

	/* Microsoft Authenticode & Software Publishing */
	OID_msIndirectData,		/* 1.3.6.1.4.1.311.2.1.4 */
	OID_msStatementType,		/* 1.3.6.1.4.1.311.2.1.11 */
	OID_msSpOpusInfo,		/* 1.3.6.1.4.1.311.2.1.12 */
	OID_msPeImageDataObjId,		/* 1.3.6.1.4.1.311.2.1.15 */
	OID_msIndividualSPKeyPurpose,	/* 1.3.6.1.4.1.311.2.1.21 */
	OID_msOutlookExpress,		/* 1.3.6.1.4.1.311.16.4 */

	OID_certAuthInfoAccess,		/* 1.3.6.1.5.5.7.1.1 */
	OID_sha1,			/* 1.3.14.3.2.26 */
	OID_sha256,			/* 2.16.840.1.101.3.4.2.1 */
	OID_sha384,			/* 2.16.840.1.101.3.4.2.2 */
	OID_sha512,			/* 2.16.840.1.101.3.4.2.3 */
	OID_sha224,			/* 2.16.840.1.101.3.4.2.4 */

	/* Distinguished Name attribute IDs [RFC 2256] */
	OID_commonName,			/* 2.5.4.3 */
	OID_surname,			/* 2.5.4.4 */
	OID_countryName,		/* 2.5.4.6 */
	OID_locality,			/* 2.5.4.7 */
	OID_stateOrProvinceName,	/* 2.5.4.8 */
	OID_organizationName,		/* 2.5.4.10 */
	OID_organizationUnitName,	/* 2.5.4.11 */
	OID_title,			/* 2.5.4.12 */
	OID_description,		/* 2.5.4.13 */
	OID_name,			/* 2.5.4.41 */
	OID_givenName,			/* 2.5.4.42 */
	OID_initials,			/* 2.5.4.43 */
	OID_generationalQualifier,	/* 2.5.4.44 */

	/* Certificate extension IDs */
	OID_subjectKeyIdentifier,	/* 2.5.29.14 */
	OID_keyUsage,			/* 2.5.29.15 */
	OID_subjectAltName,		/* 2.5.29.17 */
	OID_issuerAltName,		/* 2.5.29.18 */
	OID_basicConstraints,		/* 2.5.29.19 */
	OID_crlDistributionPoints,	/* 2.5.29.31 */
	OID_certPolicies,		/* 2.5.29.32 */
	OID_authorityKeyIdentifier,	/* 2.5.29.35 */
	OID_extKeyUsage,		/* 2.5.29.37 */

	/* EC-RDSA */
	OID_gostCPSignA,		/* 1.2.643.2.2.35.1 */
	OID_gostCPSignB,		/* 1.2.643.2.2.35.2 */
	OID_gostCPSignC,		/* 1.2.643.2.2.35.3 */
	OID_gost2012PKey256,		/* 1.2.643.7.1.1.1.1 */
	OID_gost2012PKey512,		/* 1.2.643.7.1.1.1.2 */
	OID_gost2012Digest256,		/* 1.2.643.7.1.1.2.2 */
	OID_gost2012Digest512,		/* 1.2.643.7.1.1.2.3 */
	OID_gost2012Signature256,	/* 1.2.643.7.1.1.3.2 */
	OID_gost2012Signature512,	/* 1.2.643.7.1.1.3.3 */
	OID_gostTC26Sign256A,		/* 1.2.643.7.1.2.1.1.1 */
	OID_gostTC26Sign256B,		/* 1.2.643.7.1.2.1.1.2 */
	OID_gostTC26Sign256C,		/* 1.2.643.7.1.2.1.1.3 */
	OID_gostTC26Sign256D,		/* 1.2.643.7.1.2.1.1.4 */
	OID_gostTC26Sign512A,		/* 1.2.643.7.1.2.1.2.1 */
	OID_gostTC26Sign512B,		/* 1.2.643.7.1.2.1.2.2 */
	OID_gostTC26Sign512C,		/* 1.2.643.7.1.2.1.2.3 */

	OID__NR
};

extern enum OID look_up_OID(const void* data, size_t datasize);
extern int sprint_oid(const void*, size_t, char*, size_t);
extern int sprint_OID(enum OID, char*, size_t);

#endif /* _LINUX_OID_REGISTRY_H */


/*
 * Cryptographic data for the public-key subtype of the asymmetric key type.
 *
 * Note that this may include private part of the key as well as the public
 * part.
 */
struct public_key {
	void* key;
	UINT32 keylen;
	enum OID algo;
	void* params;
	UINT32 paramlen;
	bool key_is_private;
	const char* id_type;
	const char* pkey_algo;
};

extern void public_key_free(struct public_key* key);

/*
 * Public key cryptography signature data
 */
struct public_key_signature {
	struct asymmetric_key_id* auth_ids[2];
	UINT8* s;			/* Signature */
	UINT32 s_size;		/* Number of bytes in signature */
	UINT8* digest;
	UINT8 digest_size;		/* Number of bytes in digest */
	const char* pkey_algo;
	const char* hash_algo;
	const char* encoding;
};


/*
 * The key payload is four words.  The asymmetric-type key uses them as
 * follows:
 */
enum asymmetric_payload_bits {
	asym_crypto,		/* The data representing the key */
	asym_subtype,		/* Pointer to an asymmetric_key_subtype struct */
	asym_key_ids,		/* Pointer to an asymmetric_key_ids struct */
	asym_auth		/* The key's authorisation (signature, parent key ID) */
};

/*
 * Identifiers for an asymmetric key ID.  We have three ways of looking up a
 * key derived from an X.509 certificate:
 *
 * (1) Serial Number & Issuer.  Non-optional.  This is the only valid way to
 *     map a PKCS#7 signature to an X.509 certificate.
 *
 * (2) Issuer & Subject Unique IDs.  Optional.  These were the original way to
 *     match X.509 certificates, but have fallen into disuse in favour of (3).
 *
 * (3) Auth & Subject Key Identifiers.  Optional.  SKIDs are only provided on
 *     CA keys that are intended to sign other keys, so don't appear in end
 *     user certificates unless forced.
 *
 * We could also support an PGP key identifier, which is just a SHA1 sum of the
 * public key and certain parameters, but since we don't support PGP keys at
 * the moment, we shall ignore those.
 *
 * What we actually do is provide a place where binary identifiers can be
 * stashed and then compare against them when checking for an id match.
 */
struct asymmetric_key_id {
	unsigned short	len;
	unsigned char	data[];
};

struct asymmetric_key_ids {
	void* id[2];
};


typedef long time64_t;

struct x509_certificate {
	struct x509_certificate* next;
	struct x509_certificate* signer;	/* Certificate that signed this one */
	struct public_key* pub;			/* Public key details */
	struct public_key_signature* sig;	/* Signature parameters */
	char* issuer;		/* Name of certificate issuer */
	char* subject;		/* Name of certificate subject */
	struct asymmetric_key_id* id;		/* Issuer + Serial number */
	struct asymmetric_key_id* skid;		/* Subject + subjectKeyId (optional) */
	time64_t	valid_from;
	time64_t	valid_to;
	const void* tbs;			/* Signed data */
	unsigned	tbs_size;		/* Size of signed data */
	unsigned	raw_sig_size;		/* Size of sigature */
	const void* raw_sig;		/* Signature data */
	const void* raw_serial;		/* Raw serial number in ASN.1 */
	unsigned	raw_serial_size;
	unsigned	raw_issuer_size;
	const void* raw_issuer;		/* Raw issuer name in ASN.1 */
	const void* raw_subject;		/* Raw subject name in ASN.1 */
	unsigned	raw_subject_size;
	unsigned	raw_skid_size;
	const void* raw_skid;		/* Raw subjectKeyId in ASN.1 */
	unsigned	index;
	bool		seen;			/* Infinite recursion prevention */
	bool		verified;
	bool		self_signed;		/* T if self-signed (check unsupported_sig too) */
	bool		unsupported_key;	/* T if key uses unsupported crypto */
	bool		unsupported_sig;	/* T if signature uses unsupported crypto */
	bool		blacklisted;
};



struct pkcs7_signed_info {
	struct pkcs7_signed_info* next;
	struct x509_certificate* signer; /* Signing certificate (in msg->certs) */
	unsigned	index;
	bool		unsupported_crypto;	/* T if not usable due to missing crypto */
	bool		blacklisted;

	/* Message digest - the digest of the Content Data (or NULL) */
	const void* msgdigest;
	unsigned	msgdigest_len;

	/* Authenticated Attribute data (or NULL) */
	unsigned	authattrs_len;
	const void* authattrs;
	unsigned long	aa_set;
#define	sinfo_has_content_type		0
#define	sinfo_has_signing_time		1
#define	sinfo_has_message_digest	2
#define sinfo_has_smime_caps		3
#define	sinfo_has_ms_opus_info		4
#define	sinfo_has_ms_statement_type	5
	time64_t	signing_time;

	/* Message signature.
	 *
	 * This contains the generated digest of _either_ the Content Data or
	 * the Authenticated Attributes [RFC2315 9.3].  If the latter, one of
	 * the attributes contains the digest of the the Content Data within
	 * it.
	 *
	 * THis also contains the issuing cert serial number and issuer's name
	 * [PKCS#7 or CMS ver 1] or issuing cert's SKID [CMS ver 3].
	 */
	struct public_key_signature* sig;
};

struct pkcs7_message {
	struct x509_certificate* certs;	/* Certificate list */
	struct x509_certificate* crl;	/* Revocation list */
	struct pkcs7_signed_info* signed_infos;
	UINT8		version;	/* Version of cert (1 -> PKCS#7 or CMS; 3 -> CMS) */
	bool		have_authattrs;	/* T if have authattrs */

	/* Content Data (or NULL) */
	enum OID	data_type;	/* Type of Data */
	size_t		data_len;	/* Length of Data */
	size_t		data_hdrlen;	/* Length of Data ASN.1 header */
	const void* data;		/* Content Data (or 0) */
};
