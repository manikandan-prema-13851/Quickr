#include "embeded.h"
#include "asn1.h"
#include "fUtil.h"


/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((int)((y)-1))
#define  PUB_KEY_LEN 257
int ZOHO_PUB_KEY[PUB_KEY_LEN] = {
0x00, 0xe2, 0xdc, 0x77, 0x8c, 0x18, 0x02, 0x0a, 0x80, 0x37, 0xd0, 0xe1, 0x42, 0xbe, 0x2b, 0xff, 0xca, 0x8b, 0xf2, 0x16, 0x9f, 0x13, 0xe6, 0xe2, 0x0b, 0x0a, 0xf6, 0x2d, 0xe8, 0xe9, 0xb5, 0xf5, 0x9f, 0x3a, 0x99, 0x39, 0xa3, 0xcf, 0xc0, 0x0f, 0x21, 0xee, 0x70, 0xca, 0x8d, 0xdc, 0x12, 0x68, 0xfd, 0x17, 0x93, 0x8e, 0xcd, 0x94, 0x00, 0x5c, 0x4d, 0xf6, 0xa4, 0x4e, 0x32, 0x14, 0x8a, 0x72, 0x18, 0x98, 0x79, 0x58, 0x62, 0x04, 0x5a, 0x7c, 0x57, 0x3a, 0xfa, 0xd7, 0x32, 0x3f, 0xb1, 0x8f, 0x25, 0x6f, 0x36, 0x37, 0x77, 0x11, 0x47, 0x49, 0xdf, 0x5f, 0x28, 0x0b, 0x2b, 0x50, 0x3e, 0x99, 0xfd, 0x25, 0x59, 0xfc, 0x22, 0x86, 0x78, 0x2f, 0xc2, 0x94, 0xda, 0xe3, 0x13, 0xb2, 0xfb, 0x47, 0x1e, 0x0a, 0x53, 0xae, 0x4f, 0xed, 0xfc, 0x3d, 0x70, 0xf8, 0x19, 0x1d, 0xcc, 0x46, 0x6e, 0x2d, 0x99, 0x90, 0x26, 0x95, 0x0d, 0x40, 0x5e, 0xbe, 0x20, 0x88, 0x50, 0xad, 0x34, 0x37, 0xdc, 0x40, 0xc7, 0xc8, 0x29, 0x9e, 0x42, 0xf9, 0x39, 0x28, 0xcb, 0x5d, 0xda, 0xc0, 0x82, 0x6c, 0xc8, 0x90, 0x09, 0xb9, 0xff, 0x36, 0xd3, 0x76, 0x23, 0xc9, 0x27, 0x52, 0xdb, 0x4e, 0x0a, 0xdc, 0x65, 0x64, 0x89, 0x1c, 0xbe, 0x2a, 0x1b, 0xc6, 0xb5, 0x04, 0x54, 0xf9, 0xea, 0x91, 0xa2, 0x95, 0xa0, 0x12, 0x74, 0x83, 0xbd, 0xdc, 0xf8, 0xec, 0x5d, 0x50, 0x44, 0x67, 0x03, 0xba, 0xe5, 0x15, 0x81, 0xf9, 0x45, 0x7f, 0x54, 0x9d, 0x53, 0x05, 0xd1, 0x2f, 0xcd, 0x44, 0x4a, 0x88, 0x53, 0x96, 0x8d, 0xdc, 0xe2, 0x6d, 0x2f, 0x59, 0xbe, 0xee, 0xfc, 0xe0, 0xe1, 0x82, 0x01, 0x2c, 0x4c, 0xe2, 0xb8, 0x07, 0xad, 0x5e, 0xfb, 0x1e, 0xee, 0xb4, 0xf0, 0xaa, 0xb8, 0x52, 0x66, 0xf2, 0x67, 0xf5, 0xa2, 0xe8, 0xe1 };


/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
int NOT_ZOHO_SIGNER = -101;



/*
 * Check and strip the PE wrapper from around the signature and check that the
 * remnant looks something like PKCS#7.
 */
__declspec(noinline) int pefile_strip_sig_wrapper(FILE* fp, struct pefile_context* ctx, struct PEImgDetails* data) {
	struct win_certificate wrapper;
	UINT8* pkcs7;

	// Check if the signature length is valid
	if (ctx->sig_len < sizeof(wrapper)) {
		//DEBUG//printf("Signature wrapper too short\n");
		return -ELIBBAD;
	}

	if (1 != freadW(&wrapper, ctx->sig_offset, sizeof(struct win_certificate), 1, fp, data->fileSize)) {
		return -1;
	}

	//DEBUG//printf("sig wrapper = { %x, %x, %x }\n", wrapper.length, wrapper.revision, wrapper.cert_type);

	/* Check if the signature length aligns correctly */
	if (round_up(wrapper.length, 8) != ctx->sig_len) {
		//DEBUG//printf("Signature wrapper len wrong  %d   and  %d \n", round_up(wrapper.length, 8), ctx->sig_len);
		//return -ELIBBAD; // This case may happen when Signature data has embedded info for operation
	}

	// Check the revision and certificate type
	if (wrapper.revision != WIN_CERT_REVISION_2_0) {
		//DEBUG//printf("Signature is not revision 2.0\n");
		return -ENOTSUPP;
	}
	if (wrapper.cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
		//DEBUG//printf("Signature certificate type is not PKCS\n");
		return -ENOTSUPP;
	}

	/* Adjust signature length and offset */
	ctx->sig_len = wrapper.length;
	ctx->sig_offset += sizeof(wrapper);
	ctx->sig_len -= sizeof(wrapper);

	if (ctx->sig_len < 4) {
		//DEBUG//printf("Signature data missing\n");
		return -EKEYREJECTED;
	}

	/* Allocate memory for PKCS#7 data */
	pkcs7 = calloc(1, ctx->sig_len * sizeof(char));
	if (!pkcs7 || (1 != freadW(pkcs7, ctx->sig_offset, ctx->sig_len, 1, fp, data->fileSize))) {
		free(pkcs7);
		return -1;
	}

	// Print PKCS#7 data in hex format
	printAsHex(pkcs7, ctx->sig_len);

	// Parse the PKCS#7 structure
	char* buffer = pkcs7;
	char* end = buffer + ctx->sig_len;
	size_t lSize = 0;
	int ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1.0);

	if (ret >= 0) {
		ctx->pkcs = pkcs7;
		ctx->sig_len = (unsigned int)(lSize + (buffer - pkcs7));
		return 0;
	}
	else {
		free(pkcs7);
		return -ELIBBAD;
	}

	//DEBUG// Additional legacy checks removed for clarity, as they are commented out
}


/*
	PKCS7ContentInfo ::= SEQUENCE {
		contentType	ContentType ({ pkcs7_check_content_type }),
		content		[0] EXPLICIT SignedData OPTIONAL
	}

	SignedData ::= SEQUENCE {
		 version Version,
		 digestAlgorithms DigestAlgorithmIdentifiers,
		 contentInfo ContentInfo,
		 certificates
			[0] IMPLICIT ExtendedCertificatesAndCertificates
			  OPTIONAL,
		 crls
		   [1] IMPLICIT CertificateRevocationLists OPTIONAL,
		 signerInfos SignerInfos }

   DigestAlgorithmIdentifiers ::=
	 SET OF DigestAlgorithmIdentifier

   SignerInfos ::= SET OF SignerInfo

*/
__declspec(noinline) int extractRawSignedData(const char* p, size_t len, struct ExtractedSignedData* esd) {
	size_t lSize = len;
	char* buffer = (char*)p;
	char* end = buffer + lSize;
	int Status = -1;

	//DEBUG//printf("\n\n");
	int ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	//DEBUG//printf("1.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);
	//DEBUG//printf("\n\n");
	if (ret != 0) {
		return Status;
	}


	ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_OID);
	//DEBUG//printf("2.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? (unsigned)ret : ret, buffer, lSize, end);
	//DEBUG//printf("\n\n");
	if (ret != 0) {
		return Status;
	}

	if (compareOID(buffer, (int)lSize, OID_SIGNEDDATA, sizeof(OID_SIGNEDDATA)) != 0) {
		printf("3. OID for signedData not matched, so exit \n");
		for (int i = 0; i < lSize; i++)
		{
			printf("%02x ", (UINT8)buffer[i]);
		}
		for (int i = 0; i < sizeof(OID_SIGNEDDATA); i++)
		{
			printf("%02x ", (UINT8)OID_SIGNEDDATA[i]);
		}
		return -1;
	}


	//Navigate to [0]
	buffer = buffer + lSize; //Move the buffer to next element - this is only for next element of OID 
	ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
	if (ret < 0) {
		return Status;
	}
	//DEBUG//printf("4.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);
	printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
	//DEBUG//printf("\n\n");


	//Navigate to SEQUENCE
	ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return Status;
	}
	//DEBUG//printf("5.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);
	printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
	//DEBUG//printf("\n\n");


	//Get Version
	ret = mbedtls_asn1_get_int(&buffer, end, &(esd->Version));
	if (ret < 0) {
		return Status;
	}
	//DEBUG//printf("6.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);
	//DEBUG//printf("Version is  %d\n\n", esd->Version);

	if (esd->Version == 1) {	//Version must be 1
		//DEBUG//printf("Version of SignedData is 1, Check OK\n\n");
	}
	else {
		//DEBUG//printf("Version of SignedData is not 1, Check Failed\n\n");
		return Status;
	}


	//Get DigestAlgorithIdentifier
	ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
	//DEBUG//printf("7.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? (unsigned)ret : ret, buffer, lSize, end);
	if (ret < 0) {
		return Status;
	}
	printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
	//DEBUG//printf("\n\n");
	esd->DigestAlgorithmIdentifiers = buffer;
	esd->lenDigestAlgorithmIdentifiers =(int) lSize;
	buffer += lSize;



	//Get ContentInfo
	ret = mbedtls_asn1_get_tag(&buffer, end, (size_t*)&lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	//DEBUG//printf("8.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? (unsigned)ret : ret, buffer, lSize, end);
	if (ret < 0) {
		return Status;
	}
	printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
	//DEBUG//printf("\n\n");
	esd->ContentInfo = buffer;
	esd->lenContentInfo = (int)lSize;
	buffer += lSize;



	//Get Certificates
	char* start = buffer;
	ret = mbedtls_asn1_get_tag(&buffer, end, (size_t*)&lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
	//DEBUG//printf("9.  Get Certificates Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? (unsigned)ret : ret, buffer, lSize, end);
	if (ret < 0) {
		return Status;
	}
	printAsHex(start, (buffer - start) + lSize);
	//DEBUG//printf("\n\n");
	esd->Certificates = buffer;
	esd->lenCertificates = (int)lSize;
	buffer += lSize;


	//Get SignerInfo
	ret = mbedtls_asn1_get_tag(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
	//DEBUG//printf("10.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? (unsigned)ret : ret, buffer, lSize, end);
	if (ret < 0) {
		return Status;
	}
	printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
	//DEBUG//printf("\n\n");
	esd->SignerInfos = buffer;
	esd->lenSignerInfos = (int)lSize;
	buffer += lSize;

	return 0;
}


/*
*	Print the ParsedSignedData to ensure the boundaries
*/
__declspec(noinline) void printExtractedSignedData(struct ExtractedSignedData* esd) {
	//DEBUG//printf("############################    PSD Begin   ################################\n\n");
	//DEBUG//printf("Version : \t\t%d\n\n\n", esd->Version);

	//DEBUG//printf("DigestAlgorithIdentifier : ");
	printAsHex(esd->DigestAlgorithmIdentifiers, esd->lenDigestAlgorithmIdentifiers);

	//DEBUG//printf("\n\n\n");
	//DEBUG//printf("ContentInfo : ");
	printAsHex(esd->ContentInfo, esd->lenContentInfo);
	//DEBUG//printf("\n\n\n");

	//DEBUG//printf("Certificate : ");
	printAsHex(esd->Certificates, esd->lenCertificates);
	//DEBUG//printf("\n\n\n");

	//DEBUG//printf("SignerInfo : ");
	printAsHex(esd->SignerInfos, esd->lenSignerInfos);
	//DEBUG//printf("\n\n\n");

	//DEBUG//printf("############################    PSD End     ################################\n\n");
}


/*
	Ref : https://datatracker.ietf.org/doc/html/rfc2315#section-9.2
	SignerInfo ::= SEQUENCE {
		 version Version,
		 issuerAndSerialNumber IssuerAndSerialNumber,
		 digestAlgorithm DigestAlgorithmIdentifier,
		 authenticatedAttributes
		   [0] IMPLICIT Attributes OPTIONAL,
		 digestEncryptionAlgorithm
		   DigestEncryptionAlgorithmIdentifier,
		 encryptedDigest EncryptedDigest,
		 unauthenticatedAttributes
		   [1] IMPLICIT Attributes OPTIONAL
	}

	Dev Note on Calculating Hash of Auth Attr :
	Message Digest Procedure is mentioned here => https://datatracker.ietf.org/doc/html/rfc2315#section-9.3
	After reading the doc it will be cleared that Encrypted Digest is the Hash of AuthAttr
	But not sure how it is done, after days of research figured the under documented way of hasing the field
	Hash ( ChangeTagCodeFromZeroToSET ( SignerInfo -> AuthenticatedAttributes )  )
	https://social.msdn.microsoft.com/Forums/sqlserver/en-US/e80d2b86-7206-49fc-aaa1-b045b8808b7c/encrypteddigest-verification-with-bcrypt?forum=wdk
	In this link, in a comment it is mentioned that way and applying it works.
*/
__declspec(noinline) int parseSignerInfo(struct ExtractedSignedData* esd, struct ParsedSignerInfo* psignInfo) {
	char* buffer, * end;
	size_t lSize;
	int Status = -1;


	buffer = esd->SignerInfos;
	lSize = esd->lenSignerInfos;
	end = buffer + lSize;
	int i = 0;

	//Enter SEQUENCE
	int ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 0);
	if (ret < 0) {
		return ret;
	}

	ret = mbedtls_asn1_get_int(&buffer, end, &psignInfo->version);
	if (ret < 0) {
		return ret;
	}

	if (psignInfo->version != 1) {
		//DEBUG//printf("SignerInfo version does not match \n\n");
		return -1;
	}

	//Enter Subject SEQUENCE and get the Signed Certificate Serial Number
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1);
	if (ret < 0) {
		return ret;
	}

	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_INTEGER, 1);
	if (ret < 0) {
		return ret;
	}
	psignInfo->SignedCertificateSerialNumber = buffer;
	psignInfo->lenSignedCertificateSerialNumber = (int)lSize;
	buffer = buffer + lSize;

	//Enter DigestAlgo SEQUENCE
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 2);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, 6);
	if (ret < 0) {
		return ret;
	}

	//Get HashAlgo
	mbedtls_asn1_buf oid;
	oid.tag = MBEDTLS_ASN1_OID;
	oid.p = buffer;
	oid.len = lSize;

	ret = mbedtls_oid_get_md_alg(&oid, &psignInfo->ContentInfoHashAlgo);
	RETURN_ON_ERROR(ret);

	//DEBUG//printf("Algo Type in SignerInfo : %d\n\n", psignInfo->ContentInfoHashAlgo);
	buffer = buffer + lSize;

	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_NULL, 7);
	/*if (ret < 0) {
		return ret;
	}*/


	//Enter [0] AuthAttributes
	//Before parsing save the address for future Hash calculation
	char* AuthAttrHashPoint = buffer;
	int AuthAttrHashPointLen = 0;//Will fill after parse
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED, 8);
	if (ret < 0) {
		return ret;
	}
	AuthAttrHashPointLen = (int) (lSize + (buffer - AuthAttrHashPoint)); //(buffer - AuthAttrHashPoint) => Gives Offset of tag+len



	int MESSAGE_DIGEST_OID[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
	int GotMessageDigest = 0;

	//Inside the Auth Attr, the order of SEQUENCE varies, our interest is on MessageDigest Sequence only, we can find it with OID matching
	while (enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 9) >= 0) {

		char* SeqStart = buffer;
		int SeqLen = (int)lSize;

		//Now Enter OID 
		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, 10);
		if (ret < 0) {
			return ret;
		}

		if (lSize != 9) {
			//DEBUG//printf("Not message digest len mismatch %d, %d\n", 9, lSize);
			buffer = SeqStart + SeqLen;
			continue;
		}

		int i = 0;
		for (; i < lSize; i++) {
			if ((UINT8)buffer[i] != MESSAGE_DIGEST_OID[i]) {
				//DEBUG//printf("Not message digest :: index %d =>  %02x != %02x\n", i, buffer[i], MESSAGE_DIGEST_OID[i]);
				buffer = SeqStart + SeqLen;
				break;;
			}
		}


		if (i == lSize) {
			//DEBUG//printf("MessageDigest matched \n\n");
			buffer = buffer + lSize; //Parse out of OID
		}
		else {
			continue;
		}

		GotMessageDigest = 1;
		break;
	}

	if (GotMessageDigest) {


		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET, 11);
		if (ret < 0) {
			return ret;
		}

		//And get the OCTET String which has the Hash of ContentInfo
		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OCTET_STRING, 11);
		if (ret < 0) {
			return ret;
		}
		psignInfo->ContentInfoHashStrFromAuthAtr = buffer;
		psignInfo->lenContentInfoHashStrFromAuthAtr = (int)lSize;

		buffer = AuthAttrHashPoint + AuthAttrHashPointLen; //Get out of AuthAttr
	}
	else {
		//DEBUG//printf("Unable to parse through AuthAttr\n");
		return -1;
	}






	//Now Skip 2 Sequence to reach EnryptedDigest
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 12);
	if (ret < 0) {
		return ret;
	}

	//Now get the encrypteddigest OCTETSTRING
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OCTET_STRING, 13);
	if (ret < 0) {
		return ret;
	}
	psignInfo->EncryptedDigest = buffer;
	psignInfo->lenEncryptedDigest = (int)lSize;

	/*
	All fields are parsed now compute the Hash of AuthenticatedAttributes
	https://datatracker.ietf.org/doc/html/rfc2315#section-9.3
	After reading the doc it will be cleared that Encrypted Digest is the Hash of AuthAttr
	But not sure how it is done, after research and days figured the undocumented way of hasing the field
	Hash ( ChangeTagCodeFromZeroToSET ( SignerInfo -> AuthenticatedAttributes )  )
	*/

	AuthAttrHashPoint[0] = MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED;
	ret = calculateHash(psignInfo->ContentInfoHashAlgo, AuthAttrHashPoint, AuthAttrHashPointLen, &psignInfo->AuthAtrHashStr, &psignInfo->lenAuthAtrHashStr);
	if (ret < 0) {
		//DEBUG//printf("Unable to calculate hash of AuthAttr\n\n");
		return -1;
	}
	//DEBUG//printf("AuthAttrHash str : \n");
	printAsHex(psignInfo->AuthAtrHashStr, psignInfo->lenAuthAtrHashStr);
	//printf("CALCULATE HASH \n\n");
	/*for (int i = 0; i < psignInfo->lenAuthAtrHashStr; i++)
	{
		printf("%02X ", (UINT8)psignInfo->AuthAtrHashStr[i]);
	}
	printf("\n");*/
	AuthAttrHashPoint[0] = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED;


	return 0;
}


__declspec(noinline) int checkByteArrayEqual(char* left, int leftlen, char* right, int rightlen) {
	int matched = FALSE;
	if (left == NULL || right == NULL) {
		return matched;
	}
	if (leftlen == rightlen) {
		for (int i = 0; i < leftlen; i++) {
			if (left[i] != right[i]) {
				matched = FALSE;
				return matched;
			}
		}
		matched = TRUE;
		return matched;
	}
	return matched;
}

__declspec(noinline) int count(struct Certificate* list)
{
	int Certificates = 0;

	while (list != NULL)
	{
		Certificates++;
		list = list->next;
	}

	return Certificates;
}

/*
* https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 *
 *    TBSCertificate  ::=  SEQUENCE  {
	version         [0]  EXPLICIT Version DEFAULT v1,
	serialNumber         CertificateSerialNumber,
	signature            AlgorithmIdentifier,
	issuer               Name,
	validity             Validity,
	subject              Name,
	subjectPublicKeyInfo SubjectPublicKeyInfo,
	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
						 -- If present, version MUST be v2 or v3
	 subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
						 -- If present, version MUST be v2 or v3
	extensions      [3]  EXPLICIT Extensions OPTIONAL
						 -- If present, version MUST be v3
	}

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER

Validity ::= SEQUENCE {
	 notBefore      Time,
	 notAfter       Time }

Time ::= CHOICE {
	 utcTime        UTCTime,
	 generalTime    GeneralizedTime }

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 algorithm            AlgorithmIdentifier,
	 subjectPublicKey     BIT STRING  }

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
	 extnID      OBJECT IDENTIFIER,
	 critical    BOOLEAN DEFAULT FALSE,
	 extnValue   OCTET STRING
				 -- contains the DER encoding of an ASN.1 value
				 -- corresponding to the extension type identified
				 -- by extnID
	 }
  * And we want
	 SignerPublicKey
	 SignerExponent
	 SignerCertThumbprint

 Extract only the certificate which is the Signer, which can be determined by SignerInfo->SignerCertificate
  */
__declspec(noinline) int swap(struct Certificate* head, int pos1, int pos2)
{
	//DEBUG//printf("Swap %d with %d\n", pos1, pos2);
	struct Certificate* Certificate1 = 0, * Certificate2 = 0, * prev1 = 0, * prev2 = 0, * temp = 0;
	int i;

	// Get the far position among both
	const int maxPos = (pos1 > pos2) ? pos1 : pos2;

	// Get total Certificates in the list
	const int totalCertificates = count(head);
	//DEBUG//printf("Swap: Total certs  %d \n", totalCertificates);
	// Validate swap positions
	if ((pos1 <= 0 || pos1 > totalCertificates) || (pos2 <= 0 || pos2 > totalCertificates))
	{
		return -1;
	}

	// If both positions are same then no swapping required
	if (pos1 == pos2)
	{
		return 1;
	}

	//DEBUG//printf("Swap started\n");
	// Identify both Certificates to swap
	i = 1;
	temp = head;
	prev1 = NULL;
	prev2 = NULL;

	// Find Certificates to swap
	while (temp != NULL && (i <= maxPos))
	{
		if (i == pos1 - 1)
			prev1 = temp;
		if (i == pos1)
			Certificate1 = temp;

		if (i == pos2 - 1)
			prev2 = temp;
		if (i == pos2)
			Certificate2 = temp;

		temp = temp->next;
		i++;
	}

	// If both Certificates to swap are found.
	if (Certificate1 != NULL && Certificate2 != NULL)
	{
		// Link previous of Certificate1 with Certificate2
		if (prev1 != NULL)
			prev1->next = Certificate2;

		// Link previous of Certificate2 with Certificate1
		if (prev2 != NULL)
			prev2->next = Certificate1;

		// Swap Certificate1 and Certificate2 by swapping their 
		// next Certificate links
		temp = Certificate1->next;
		Certificate1->next = Certificate2->next;
		Certificate2->next = temp;

		// Make sure to swap head Certificate when swapping
		// first element.
		if (prev1 == NULL)
			head = Certificate2;
		else if (prev2 == NULL)
			head = Certificate1;
	}

	return 1;
}

/*
* Parse certificates out of ASN
* Check the chain's integrity
* Check whether the root is in trusted list
* Check the chain's integrity wrt root packed in system
*/
/*
	* Parse certificates out of ASN
	* Check the chain's integrity
	* Check whether the root is in trusted list
	* Check the chain's integrity wrt root packed in system
	*/
__declspec(noinline) int VerifyCertificateChainIntegrity(struct Certificate** certStart, char* SignedCertSerialNumber, int lenSignedCertSerialNumber, Tree_t* TrustedCAtree) {

	int ret = 0;

	//Lets sort it for easy reference, start with finding the leaf signer
	struct Certificate* temp = *certStart;
	int counter = 1, startFound = FALSE;
	while (temp) {
		if (temp->SerialNumberLen == lenSignedCertSerialNumber) {
			int matched = TRUE;
			for (int i = 0; i < lenSignedCertSerialNumber; i++) {
				if (temp->SerialNumber[i] != SignedCertSerialNumber[i]) {
					matched = FALSE; break;
				}
			}
			if (matched) {
				//match found, now we just wanted to keep it as *certStart
				ret = swap(*certStart, 1, counter);
				//DEBUG//printf("Swap return status %d\n", ret);
				*certStart = temp;
				startFound = TRUE;
				break;
			}
		}
		counter++;
		temp = temp->next;
	}

	if (startFound) {
		//DEBUG//printf("Found the leaf signer certificate, \n");
		printCertificate(*certStart);
		
	}
	else {
		//printf("Cannot find the leaf signer certificate, so the chain is invalid\n");
		return -1;
	}

	//DEBUG//printf("-------------------------------------------------------------------------------\n\n");
	temp = *certStart;
	//DEBUG//printf("After 1st Swap ParsedCertificate Details Starts:\n");
	while (temp) {
		//printCertificate(temp);
		temp = temp->next;
	}
	//DEBUG//printf("After 1st Swap ParsedCertificate Details Ends:\n");
	//DEBUG//printf("-------------------------------------------------------------------------------\n\n");
	//Lets proceed to sort the chain
	temp = *certStart;
	counter = 1;

	while (temp && temp->next) {
		struct Certificate* innerTemp = temp->next;
		int innerCounter = counter + 1, foundIssuer = FALSE;
		while (innerTemp) {
			int matched = TRUE;
			if (temp->IssuerName != NULL && innerTemp->Name != NULL && false) {
				if (innerTemp->NameLen == temp->IssuerNameLen) {
					int i;
					for (i = 0; i < temp->IssuerNameLen; i++) {
						if (temp->IssuerName[i] != innerTemp->Name[i]) {
							matched = FALSE; break;
						}
					}
					if (matched) {
						swap(*certStart, counter + 1, innerCounter);
						foundIssuer = TRUE;
						break;
					}
				}
				else {
					matched = FALSE;
				}
			}
			else {

				if (temp->IssuerRDN == NULL || innerTemp->SubjectRDN == NULL) {
					matched = FALSE;
					break;
				}
				if (innerTemp->SubjectRDNLen == temp->IssuerRDNLen) {
					int i;
					for (i = 0; i < temp->IssuerRDNLen; i++) {

						if (temp->IssuerRDN[i] != innerTemp->SubjectRDN[i]) {
							matched = FALSE; break;
						}
					}
					if (matched) {
						swap(*certStart, counter + 1, innerCounter);
						foundIssuer = TRUE;
						break;
					}
				}
			}
			innerCounter++;
			innerTemp = innerTemp->next;
		}

		if (foundIssuer) {
			//DEBUG//printf("Found the issuer certificate \n");
			printAsText(temp->Name, temp->NameLen);
			//DEBUG//printf(" ---->  \n");
			printAsText(temp->next->Name, temp->next->NameLen);
		}
		else {
			//DEBUG//printf("Cannot find the issuer certificate, so delete the remaining certificates\n");

			struct Certificate* head = temp->next;
			while (head != NULL)
			{
				innerTemp = head;
				head = head->next;
				if (innerTemp->tbsCertHashValue) {
					free(innerTemp->tbsCertHashValue);
					innerTemp->tbsCertHashValue = NULL;
					innerTemp->tbsCertHashValueLen = 0;
				}
				if (innerTemp->Thumbprint) {
					free(innerTemp->Thumbprint);
					innerTemp->Thumbprint = NULL;
					innerTemp->ThumbprintLen = 0;
				}
				free(innerTemp);
			}
			temp->next = NULL;
		}

		counter++;
		temp = temp->next;
	}
	/*
		printf("\n\nFinal List:\n");
		printf("-------------------------------------------------------------------------------\n\n");
		temp = *certStart;
		while (temp) {
			printCertificate(temp);
			temp = temp->next;
		}
		printf("-------------------------------------------------------------------------------\n\n");
	*/

	//Start checking chain integrity
	temp = *certStart;
	while (temp && TrustedCAtree) {
		//check if it is in trusted certs and also ensure its public key matches
		struct Node_t* n = NULL;
		char* name = (char*)calloc((temp->SubjectRDNLen) + 1, sizeof(char));
		if (name) {
			//ZeroMemory(name,((unsigned long long)temp->SubjectRDNLen + 1));
			memcpy(name, temp->SubjectRDN, temp->SubjectRDNLen);


			n = searchNode_t(name, TrustedCAtree->root, (Compare)CmpStr);
		}
		if (n != NULL) {
			//DEBUG//printf("Verification Success :) The cert \"%s\" is in Root , ", name);
			free(name);
			return 1;
		}

		if (temp->next) {
			//Issure is also packed, We got to ensure the integrity of certificate wrt to issuer
			ret = VerifySignature(temp->tbsCertHashValue, temp->tbsCertHashValueLen, temp->SignatureValue, temp->SignatureValueLen, temp->next->SubjectPublicKeyInfo, temp->next->SubjectPublicKeyInfoLen, temp->next->SubjectPublicKeyExponent, temp->Algorithm);
			if (ret < 0)
			{
				//DEBUG//printf("Verification Failed, Invalid certificate chain %x\n\n", ret);
				free(name);
				return -1;
			}
			else {
				//DEBUG//printf("Verification Success :) so, ");
				free(name);

				printAsText(temp->Name, temp->NameLen);
				//DEBUG//printf(" Signed by  ");
				printAsText(temp->next->Name, temp->next->NameLen);
			}
		}
		else {
			//No next cert, 
			//so check if this is self signed if so ensure it is trusted in AuthRoots 
			//else check for its issuer from trusted roots.
			if (checkByteArrayEqual(temp->IssuerRDN, temp->IssuerRDNLen, temp->SubjectRDN, temp->SubjectRDNLen)) {
				//check if it is in trusted certs and also ensure its public key matches
				free(name);
				struct Node_t* n = NULL;
				char* name = (char*)calloc(((unsigned long long)(temp->SubjectRDNLen) + 1), sizeof(char));
				if (name) {
					memcpy(name, temp->SubjectRDN, temp->SubjectRDNLen);
					n = searchNode_t(name, TrustedCAtree->root, (Compare)CmpStr);
				}

				if (n == NULL) {
					//DEBUG//printf("Verification Failed :) Provided root \"%s\" is not in Trusted List\n", name);
					free(name);
					return -1; //Invalid certificate
				}
				else {
					free(name);
					if (checkByteArrayEqual(temp->SubjectPublicKeyInfo, temp->SubjectPublicKeyInfoLen, n->value->SubjectPublicKeyInfo, n->value->SubjectPublicKeyInfoLen) && (temp->SubjectPublicKeyExponent == n->value->SubjectPublicKeyExponent)) {
						//DEBUG//printf("Verification Success :) so, ");
						printAsText(temp->Name, temp->NameLen);
						//DEBUG//printf(" Is available in Trusted cert repo\n  ");
						return 1;	//Success
					}
					else {

						//DEBUG//printf("Verification Failed :) Provided root Publickey not matched with the one in Trusted List :: !!FRAUDALERT!!\n");
						return -1; //Invalid certificate
					}
				}
			}
			else {
				//Get the root from trusted certs and perform VerifySignature
				free(name);
				int issurerdnlen = temp->IssuerRDNLen + 1;
				char* name = (char*)calloc(issurerdnlen, sizeof(char));
				if (name) {
					ZeroMemory(name, issurerdnlen);
					memcpy(name, temp->IssuerRDN, temp->IssuerRDNLen);
				}
				struct 	Node_t* n = searchNode_t(name, TrustedCAtree->root, (Compare)CmpStr);

				if (n == NULL) {
					//DEBUG//printf("Verification Failed :) Provided root \"%s\" is not in Trusted List\n", name);
					free(name);
					return -1; //Invalid certificate
				}
				else {
					free(name);
					ret = VerifySignature(temp->tbsCertHashValue, temp->tbsCertHashValueLen, temp->SignatureValue, temp->SignatureValueLen, n->value->SubjectPublicKeyInfo, n->value->SubjectPublicKeyInfoLen, n->value->SubjectPublicKeyExponent, temp->Algorithm);
					if (ret < 0)
					{
						//DEBUG//printf("Verification Failed, Invalid certificate chain %x\n\n", ret);
						return -1;
					}
					else {
						//DEBUG//printf("Verification Success :) so, ");
						printAsText(temp->Name, temp->NameLen);
						//DEBUG//printf(" Signed by  ");
						printAsText(n->value->Name, n->value->NameLen);
						return 1;		//Success
					}
				}
			}
		}
		temp = temp->next;
	}

	return 1;
}


__declspec(noinline) int parseSignerCert(struct ExtractedSignedData* esd, char* SignedCertSerialNumber, int lenSignedCertSerialNumber, struct ParsedCertInfo* pcert, Tree_t* TrustedCAtree) {

	char* buffer, * end, * start, * holder;
	size_t lSize;
	int Status = -1;

	buffer = esd->Certificates;
	lSize = (size_t)esd->lenCertificates;
	end = buffer + lSize;
	int ret;
	int certParsed = 0;


	start = buffer;
	holder = buffer;



	struct Certificate* certStart = 0, * last = 0;

	//Enter Certificate SEQUENCE
	while (enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1) >= 0) {

		char* SeqStart = buffer;
		int lenSeqStart = (int)lSize;

		//printAsHex(start, (buffer - start) + lSize);
		struct Certificate* cert = (struct Certificate*)calloc(1, sizeof(struct Certificate));
		if (cert)
			cert->next = NULL;

		ret = ParseCertificate(start, end, (buffer - start) + lSize, cert);
		if (ret >= 0) {

			if (certStart) {
				last->next = cert;
				last = cert;
			}
			else {
				certStart = cert;
				last = cert;
			}
		}
		else {
			if (cert) {
				if (cert->Thumbprint) {
					free(cert->Thumbprint);
				}
				if (cert->tbsCertHashValue) {
					free(cert->tbsCertHashValue);
				}
				free(cert);
			}
			cert = NULL;
		}

		buffer = SeqStart + lenSeqStart;
		start = buffer;
	}

	struct Certificate* temp = certStart;

	//while (temp) {
	//	printf("cert1\n");
	//	temp = temp->next;
	//}
	//DEBUG//printf("Extracted ParsedCertificate Details Starts:\n");
	/*while (temp) {
		break;
		printCertificate(temp);

		printf("ParsedCertificate Details :\n");
		printf("Name :");
		printAsText(temp->Name, temp->NameLen);
		for (int i = 0; i < temp->NameLen; i++)
		{
			printf("%c", (UINT8)temp->Name[i]);
		}
		printf("\n");
		printf("SubjectRDN :");
		printAsHex(temp->SubjectRDN, temp->SubjectRDNLen);
		printf("Issuer :");
		printAsText(temp->IssuerName, temp->IssuerNameLen);
		for (int i = 0; i < temp->IssuerNameLen; i++)
		{
			printf("%c", (UINT8)temp->IssuerName[i]);
		}
		printf("\n");
		printf("IssuerRDN :");
		printAsHex(temp->IssuerRDN, temp->IssuerRDNLen);
		printf("Thumbprint :");
		printAsHex(temp->Thumbprint, temp->ThumbprintLen);
		printf("SerialNumber :");
		printAsHex(temp->SerialNumber, temp->SerialNumberLen);
		printf("Algorithm : %d\n", temp->Algorithm);
		printf("Public Key :");
		printAsHex(temp->SubjectPublicKeyInfo, temp->SubjectPublicKeyInfoLen);
		printf("Public Key Exponent: %d\n\n\n", temp->SubjectPublicKeyExponent);

		temp = temp->next;
	}*/
	//DEBUG//printf("Extracted ParsedCertificate Details Ends:\n");

	// exit here 
	if (VerifyCertificateChainIntegrity(&certStart, SignedCertSerialNumber, lenSignedCertSerialNumber, TrustedCAtree) >= 0) {
		//DEBUG//printf("Certificate chain is valid\n");
		pcert->CertChainVerified = 1;
	}
	else {
		pcert->CertChainVerified = 0;
		//DEBUG//printf("Certificate chain is invalid\n");
		
		temp = certStart;
		while (temp) {
			struct Certificate* nextTemp = temp->next;
			if (temp->tbsCertHashValue)
				free(temp->tbsCertHashValue);
			if (temp->Thumbprint)
				free(temp->Thumbprint);
			free(temp);
			temp = nextTemp;
		}


		return -1;
	}
	//printf("%d \n", pcert->CertChainVerified);

	if (certStart && checkByteArrayEqual(certStart->SerialNumber, certStart->SerialNumberLen, SignedCertSerialNumber, lenSignedCertSerialNumber)) {
		pcert->SignerPublicKey = certStart->SubjectPublicKeyInfo;
		pcert->lenSignerPublicKey = certStart->SubjectPublicKeyInfoLen;
		pcert->SignerExponent = certStart->SubjectPublicKeyExponent;
		pcert->SigerCert = certStart;
		certParsed = 1;
	}

	if (certParsed) {
		//DEBUG//printf("1.  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);
		printAsHex(buffer, ((lSize > 10) ? 10 : lSize));
		//DEBUG//printf("\n\n");
	}

	return 0;

}


/*
* Parse the each extracted info
*/
__declspec(noinline) int verifyCertficateData(struct ExtractedSignedData* esd, struct ParsedSignedData* psd, Tree_t* TrustedCAtree) {
	//First lets start with Certinfo, so we should not waste resource on non Zoho binaries
	//First lets start with Certinfo, so we should not waste resource on non Zoho binaries

	int ret = parseSignerCert(esd, psd->ParsedSignerInfo.SignedCertificateSerialNumber, psd->ParsedSignerInfo.lenSignedCertificateSerialNumber, &(psd->ParsedCertInfo), TrustedCAtree);
	return ret;
}


/*
* General structure ref : https://datatracker.ietf.org/doc/html/rfc2315#section-7
* Apart from general structure, MSCode had private structure which is defined in a doc
* http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
*
* ContentInfo ::= SEQUENCE {
	 contentType ContentType,
	 content
	   [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
	}

	ContentType ::= OBJECT IDENTIFIER

	This field contains two fields:
contentType must be set to SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4).
content must be set to an SpcIndirectDataContent structure, which is described later.

	SpcIndirectDataContent ::= SEQUENCE {
		data                    SpcAttributeTypeAndOptionalValue,
		messageDigest           DigestInfo
	} --#public�

	SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
		type                    ObjectID,
		value                   [0] EXPLICIT ANY OPTIONAL
	}

	DigestInfo ::= SEQUENCE {
		digestAlgorithm     AlgorithmIdentifier,
		digest              OCTETSTRING
	}

	AlgorithmIdentifier    ::=    SEQUENCE {
		algorithm           ObjectID,
		parameters          [0] EXPLICIT ANY OPTIONAL
	}


*
*/
__declspec(noinline) int parseContentInfo(struct ExtractedSignedData* esd, struct ParsedContentInfo* pconInfo) {
	char* buffer, * end;
	size_t lSize;
	int Status = -1;


	buffer = esd->ContentInfo;
	lSize = esd->lenContentInfo;
	end = buffer + lSize;
	int i = 0;

	//Skip OBJIdentifier 
	int ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, 0);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC, 1);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 2);
	if (ret < 0) {
		return ret;
	}
	//This is where we need to calculate Hash of ContentInfo, store this address and len
	//Hash (  ContentInfo -> [0] -> Sequence (Just Value and exclude the Tag And Length)   )
	char* contInfoHashCalcPoint = buffer;
	int contInfoHashCalcPointLen = (int)lSize;


	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 3);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 4);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 5);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, 6);
	if (ret < 0) {
		return ret;
	}

	mbedtls_asn1_buf oid;
	oid.tag = MBEDTLS_ASN1_OID;
	oid.p = buffer;
	oid.len = lSize;

	// printf("Content (%zu bytes): \n", lSize);
	// for (size_t i = 0; i < lSize; ++i) {
	// 	printf("%02X ", buffer[i]);
	// }
	// printf("\n");

	// printf("Algo Type : %d\n\n", pconInfo->PEHashAlgo);
	ret = mbedtls_oid_get_md_alg(&oid, &pconInfo->PEHashAlgo);
	// printf("return from this %d\n", ret);
	if (ret < 0) {
		return ret;
	}
	// printf("Algo Type : %d\n\n", pconInfo->PEHashAlgo);
	//DEBUG//printf("Algo Type : %d\n\n", pconInfo->PEHashAlgo);
	buffer = buffer + lSize;

	//Now we got the Algo, so calculate hash of contentinfo now
	ret = calculateHash(pconInfo->PEHashAlgo, contInfoHashCalcPoint, contInfoHashCalcPointLen, &pconInfo->ContentInfoHashStr, &pconInfo->lenContentInfoHashStr);
	if (ret < 0) {
		//DEBUG//printf("Unable to calculate hash of ContentInfo\n\n");
		return ret;
	}

	//DEBUG//printf("ContentInfo Hash str : \n");
	printAsHex(pconInfo->ContentInfoHashStr, pconInfo->lenContentInfoHashStr);


	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_NULL, 7);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OCTET_STRING, 8);
	if (ret < 0) {
		return ret;
	}
	pconInfo->PEHashStr = buffer;
	pconInfo->lenPEHashStr = (int)lSize;

	return 0;
}


__declspec(noinline) int IsZohoSignature(struct ParsedCertInfo* pcert) {
	if (pcert->lenSignerPublicKey != PUB_KEY_LEN) {
		//DEBUG//printf("Length of PUB KEY does not match %d != %d\n\n", pcert->lenSignerPublicKey, PUB_KEY_LEN);
		return 0;
	}

	for (int i = 0; i < PUB_KEY_LEN; i++) {
		if ((UINT8)pcert->SignerPublicKey[i] != ZOHO_PUB_KEY[i]) {
			return 0;
		}
	}

	return 1;
}


/*v

DevNote: The term SignedData is denoted to the parent wrapper of CMS data
Ref: https://datatracker.ietf.org/doc/html/rfc2315#section-9

Verify in following order :
	1. CertInfo is zohocorp signer
	2. Hash_pe_in_contentInfo    ===     Hash_pe
	3. Hash_of_contentInfo       ===     Hash_of_contentInfo_in_AuthAttr
	4. Decrypt the EncryptedDigest                     => Hash_from_encrypteddigest
	5. Hash_from_encrypteddigest ===     Hash_of_authAttr
*/
__declspec(noinline) int isZohoBinary(FILE* fp, char* buffer, size_t lSize, struct pefile_context* ctx, struct PEImgDetails* peSignInfo, Tree_t* TrustedCAtree, struct PEImgDetails* data) {

	int ret = 0;
	//for (size_t i = 0; i < 14000; i++)
	//{
	//	printf("%02X ", (UINT8)buffer[i]);
	//}
	//printf("\n"); 

	peSignInfo->verified = 0;


	struct Certficate* temp = NULL;
	//Extract pkcs#7 data
	struct ExtractedSignedData esd;
	struct ParsedSignedData psd;
	psd.digest = NULL;
	ret = extractRawSignedData(buffer, ctx->sig_len, &esd);
	if (ret < 0) {
		//DEBUG//printf("Unable to extract PKCS#7 data\n\n");
		peSignInfo->errorCode = IS_ZOHO_BINARY_EXTRACT_RAW_SIGNED_DATA;
		ret = -1;
		goto Acleanup;
	}

	printExtractedSignedData(&esd);

	//Parse pkcs#7 data

	//Get the SignerInfo parsed  
	if (parseSignerInfo(&esd, &psd.ParsedSignerInfo) < 0) {
		peSignInfo->errorCode = IS_ZOHO_BINARY_PARSE_SIGNER_INFO;
		//DEBUG//printf("Unable to parse SignerInfo\n\n");
		ret = -1;
		goto Acleanup;
	}

	//1. CertInfo is signer
	if (verifyCertficateData(&esd, &psd, TrustedCAtree) < 0) {
		//DEBUG//printf("Chain is Invalid, so stop continuing the checks\n");
		if (psd.ParsedSignerInfo.AuthAtrHashStr) {
			free(psd.ParsedSignerInfo.AuthAtrHashStr);
			psd.ParsedSignerInfo.lenAuthAtrHashStr = 0;
			psd.ParsedSignerInfo.AuthAtrHashStr = NULL;
		}
		peSignInfo->errorCode = IS_ZOHO_BINARY_VERIFY_CERTFICATE_DATA;
		ret = -1;
		goto Acleanup;
	}

	//2. Hash_pe_in_contentInfo === Hash_pe
	//Get ContentInfo parsed
	if (parseContentInfo(&esd, &psd.ParsedContentInfo) < 0) {
		peSignInfo->errorCode = IS_ZOHO_BINARY_PARSE_CONTENT_INFO;
		ret = -1;
		goto cleanup;
	}
	//Get PE Hash
	ret = pefile_digest_pe(fp, (unsigned int) lSize, ctx, psd.ParsedContentInfo.PEHashAlgo, & psd.digest, & psd.digestLen, data);
	//exit here
	//printf("")
	if (ret < 0) {
		//printf("Error getting hash of PE %d\n",ret);
		//return ret;
		peSignInfo->errorCode = IS_ZOHO_BINARY_PEFILE_DIGEST_PE;
		goto cleanup;
	}
	//DEBUG//printf("PE Hash value calculated : \n");
	printAsHex(psd.digest, psd.digestLen);
	//DEBUG//printf("\n\n");

	//DEBUG//printf("PE Hash value from contentinfo : \n");
	printAsHex(psd.ParsedContentInfo.PEHashStr, psd.ParsedContentInfo.lenPEHashStr);
	//DEBUG//printf("\n\n");


	//Now compare the PEHash calculated with PEHash embedded in contentinfo blob
	if (psd.digestLen != psd.ParsedContentInfo.lenPEHashStr) {
		//DEBUG//printf("Calculated Digest does not match with embedded PE Digest :: Length not match\n\n");
		peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	for (int i = 0; i < psd.digestLen; i++) {
		if (psd.digest[i] != psd.ParsedContentInfo.PEHashStr[i]) {
			//printf("Calculated Digest does not match with embedded PE Digest:: index  %d\n\n", i);
			peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
			ret = -1;
			goto cleanup;
		}
	}

	//DEBUG//printf("Calculated Digest MATCHED with embedded PE Digest\n\n");



	//3. Hash_of_contentInfo       ===     Hash_of_contentInfo_in_AuthAttr
	//Now compare the ContentInfo calculated with hash embedded in AuthAttr
	if (psd.ParsedContentInfo.lenContentInfoHashStr != psd.ParsedSignerInfo.lenContentInfoHashStrFromAuthAtr) {
		//DEBUG//printf("Calculated ContentInfo Digest does not match with embedded ContentInfo Digest from AuthAttr:: Length not match\n\n");
		peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	for (int i = 0; i < psd.ParsedContentInfo.lenContentInfoHashStr; i++) {
		if (psd.ParsedContentInfo.ContentInfoHashStr[i] != psd.ParsedSignerInfo.ContentInfoHashStrFromAuthAtr[i]) {
			//DEBUG//printf("Calculated ContentInfo Digest does not match with embedded ContentInfo Digest from AuthAttr:: index  %d\n\n", i);
			peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
			ret = -1;
			goto cleanup;
		}
	}
	//DEBUG//printf("Calculated ContentInfo Digest MATCHED with embedded ContentInfo Digest from AuthAttr\n\n");



	//4. Verify the encrypteddigest
	ret = VerifySignature(psd.ParsedSignerInfo.AuthAtrHashStr, psd.ParsedSignerInfo.lenAuthAtrHashStr, psd.ParsedSignerInfo.EncryptedDigest, psd.ParsedSignerInfo.lenEncryptedDigest, psd.ParsedCertInfo.SignerPublicKey, psd.ParsedCertInfo.lenSignerPublicKey, psd.ParsedCertInfo.SignerExponent, psd.ParsedSignerInfo.ContentInfoHashAlgo);
	if (ret < 0)
	{
		peSignInfo->errorCode = IS_ZOHO_BINARY_VERIFY_SIGN_FAILED;
		//DEBUG//printf("Verification Failed %x\n\n", ret);
		ret = -1;
		goto cleanup;
	}
	else {
		////DEBUG//printf("Verification Success :) So, the hash of PE is in match with signer certificate\n\n\n");
		//peSignInfo->verified = 1;

		//printf("%d ==> %s \n %d = => %s \n", psd.ParsedCertInfo.SigerCert->NameLen,psd.ParsedCertInfo.SigerCert->Name,psd.ParsedCertInfo.SigerCert->ThumbprintLen,psd.ParsedCertInfo.SigerCert->Thumbprint);
		//sigCharArray(&psd.ParsedCertInfo.SigerCert->Name, psd.ParsedCertInfo.SigerCert->NameLen);
		persistCharArray(&psd.ParsedCertInfo.SigerCert->Name, psd.ParsedCertInfo.SigerCert->NameLen);
		//persistCharArray(&psd.ParsedCertInfo.SigerCert->Thumbprint, psd.ParsedCertInfo.SigerCert->ThumbprintLen);


		strDataCopy(&peSignInfo->publisher, (psd.ParsedCertInfo.SigerCert->Name));

		//printf("%s", psd.ParsedCertInfo.SigerCert->Name);
		int count = 0;
		fill_oid_name(psd.ParsedSignerInfo.ContentInfoHashAlgo, &peSignInfo->signAlg);
		char buffer1[200] = { 0 };
		//printf("%d\n\n", strlen(psd.ParsedCertInfo.SigerCert->Thumbprint));
		//persistCharArray(&psd.ParsedCertInfo.SigerCert->Thumbprint, 40);
		char* dupThumbprint = psd.ParsedCertInfo.SigerCert->Thumbprint;
		//for (DWORD i = 0; i < 40; i++)
		//{
		//	//count = strlen(buffer1);
		//	sprintf((char*)&buffer1[count], "%02X", (UINT8)(dupThumbprint)[i]);
		//	count++;
		//}


		if (psd.ParsedCertInfo.SigerCert->ThumbprintLen == 20) {
			for (int i = 0; i < psd.ParsedCertInfo.SigerCert->ThumbprintLen; i++) {
				if (count >= 100) // Prevent overflow in buffer1
					break;

				// Buffer for a single byte's hex representation (2 characters + null terminator)
				char a[3];
				sprintf(a, "%02X", (UINT8)(psd.ParsedCertInfo.SigerCert->Thumbprint)[i]);

				// Copy the hex representation into buffer1
				buffer1[count * 2] = a[0];
				buffer1[count * 2 + 1] = a[1];
				count++;
			}

			// Null-terminate the string in buffer1
			buffer1[count * 2] = '\0';

			// Copy buffer1 to the thumbprint field
			strDataCopy(&peSignInfo->thumbprint, buffer1);
		}

		peSignInfo->verified = 1;

	}

	if (IsZohoSignature(&(psd.ParsedCertInfo))) {
		//DEBUG//printf("And this is Zoho Signature\n\n");
		//peSignInfo->IsZohoSigned = 1;
	}
	else {
		//DEBUG//printf("And this is Not Zoho Signature\n\n");
		//peSignInfo->IsZohoSigned = 0;
		ret = NOT_ZOHO_SIGNER;
		goto nameCleanup;
		//return NOT_ZOHO_SIGNER;
	}

nameCleanup:
	if (psd.ParsedCertInfo.SigerCert->Name)
		free(psd.ParsedCertInfo.SigerCert->Name);

cleanup:
	//temp = ;

	if (psd.digest!=NULL) {
		free(psd.digest);
		psd.digest = NULL;
	}
	while (psd.ParsedCertInfo.SigerCert) {
		temp =(struct Certficate*) psd.ParsedCertInfo.SigerCert;

		//printCertificate(psd.ParsedCertInfo.SigerCert);
		if (psd.ParsedCertInfo.SigerCert->tbsCertHashValue) {
			free(psd.ParsedCertInfo.SigerCert->tbsCertHashValue);
		}
		if (psd.ParsedCertInfo.SigerCert->Thumbprint) {
			free(psd.ParsedCertInfo.SigerCert->Thumbprint);
		}
		psd.ParsedCertInfo.SigerCert = psd.ParsedCertInfo.SigerCert->next;
		if (temp)
			free(temp);
	}

	if (psd.ParsedContentInfo.ContentInfoHashStr)
		free(psd.ParsedContentInfo.ContentInfoHashStr);
	if (psd.ParsedSignerInfo.AuthAtrHashStr)
		free(psd.ParsedSignerInfo.AuthAtrHashStr);


	return ret;
Acleanup:
	return ret;
}

