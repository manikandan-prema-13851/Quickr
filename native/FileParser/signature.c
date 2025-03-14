#include "signature.h"


_declspec(noinline) void ReverseMemCopy(BYTE* pbDest, BYTE const* pbSource, DWORD cb)
{
	for (DWORD i = 0; i < cb; i++)
	{
		pbDest[i] = pbSource[i];
	}
}


//_declspec(noinline) NTSTATUS VerifySignature(_In_reads_bytes_(MessageLength) 	PBYTE           MessageDigest, _In_       DWORD           MessageDigestLength, _In_reads_bytes_(SignatureBlobLength) 	PBYTE           SignatureBlob, _In_       DWORD           SignatureBlobLength,
//	char* PublicKeyModulus,    // Pointer to the RSAPUBKEY blob.
//	int lenPublicKeyModulus, int PublicKeyExponent, mbedtls_md_type_t algo)

_declspec(noinline) NTSTATUS VerifySignature(
		_In_reads_bytes_(MessageDigestLength) PBYTE MessageDigest,        // Pointer to the message digest
		_In_ DWORD MessageDigestLength,                                       // Length of the message digest
		_In_reads_bytes_(SignatureBlobLength) PBYTE SignatureBlob,        // Pointer to the signature blob
		_In_ DWORD SignatureBlobLength,                                       // Length of the signature blob
		_In_ char* PublicKeyModulus,                                          // Pointer to the RSAPUBKEY blob
		_In_ int lenPublicKeyModulus,                                         // Length of the PublicKeyModulus
		_In_ int PublicKeyExponent,                                           // Public key exponent
		_In_ mbedtls_md_type_t algo                                           // Hash algorithm type (e.g., SHA-256)
	)
{
	NTSTATUS                Status;
	BCRYPT_KEY_HANDLE       KeyHandle = NULL;
	BCRYPT_ALG_HANDLE       RsaAlgHandle = NULL;


	//
	// Open a DSA algorithm handle
	//

	Status = BCryptOpenAlgorithmProvider(
		&RsaAlgHandle,
		BCRYPT_RSA_ALGORITHM,
		MS_PRIMITIVE_PROVIDER,
		0);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}

	//
	// Import the public key
	//

	///////////////////////////////////////////////////////////////////////////////////////////

	HRESULT hr = S_OK;

	//DEBUG//printf("VerifySignatures Algo  %d\n", algo);

	//DEBUG//printf("ImportRsaPublicKey Enters\n");
	printAsHex(PublicKeyModulus, lenPublicKeyModulus);
	//DEBUG//printf("\n\n");

	PBYTE pbPublicKey = NULL;    // Receives a handle the imported public key.


	DWORD cbKey = 0;

	// Layout of the RSA public key blob:

	//  +----------------------------------------------------------------+
	//  |     BCRYPT_RSAKEY_BLOB    | BE( dwExp ) |   BE( Modulus )      |
	//  +----------------------------------------------------------------+
	//
	//  sizeof(BCRYPT_RSAKEY_BLOB)       cbExp           cbModulus 
	//  <--------------------------><------------><---------------------->
	//
	//   BE = Big Endian Format                                                     

	DWORD cbModulus = (lenPublicKeyModulus);
	DWORD dwExp = PublicKeyExponent;
	DWORD cbExp = (dwExp & 0xFF000000) ? 4 :
		(dwExp & 0x00FF0000) ? 3 :
		(dwExp & 0x0000FF00) ? 2 : 1;

	//DEBUG//printf("cbExp %d\n", cbExp);

	BCRYPT_RSAKEY_BLOB* pRsaBlob;
	PBYTE pbCurrent;

	hr = DWordAdd(cbModulus, sizeof(BCRYPT_RSAKEY_BLOB), &cbKey);

	if (FAILED(hr))
	{
		//DEBUG//printf("DWordAdd Failed %d\n", hr);
		goto done;
	}

	cbKey += cbExp;

	pbPublicKey = (BYTE*)CoTaskMemAlloc(cbKey);
	if (NULL == pbPublicKey)
	{
		hr = E_OUTOFMEMORY;
		goto done;
	}

	ZeroMemory(pbPublicKey, cbKey);
	pRsaBlob = (BCRYPT_RSAKEY_BLOB*)(pbPublicKey);

	// Make the Public Key Blob Header
	pRsaBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
	pRsaBlob->BitLength = lenPublicKeyModulus * 8;
	pRsaBlob->cbPublicExp = cbExp;
	pRsaBlob->cbModulus = cbModulus;
	pRsaBlob->cbPrime1 = 0;
	pRsaBlob->cbPrime2 = 0;

	pbCurrent = (PBYTE)(pRsaBlob + 1);

	printAsHex(pbPublicKey, cbKey);
	//DEBUG//printf("\n\n");
	// Copy pubExp Big Endian 
	ReverseMemCopy(pbCurrent, (PBYTE)&dwExp, cbExp);
	pbCurrent += cbExp;
	printAsHex(pbPublicKey, cbKey);
	//DEBUG//printf("\n\n");

	// Copy Modulus Big Endian 
	ReverseMemCopy(pbCurrent, PublicKeyModulus, cbModulus);

	//DEBUG//printf("RSABlob In Method  %d :\n", cbKey);
	printAsHex(pbPublicKey, cbKey);
	//DEBUG//printf("\n\n");

	// Set the key.
	hr = BCryptImportKeyPair(
		RsaAlgHandle,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		&KeyHandle,
		(PUCHAR)pbPublicKey,
		cbKey,
		0
	);
	if (!NT_SUCCESS(hr))
	{
		//DEBUG//printf("ImportKey Failed to Init %x\n\n", hr);
		goto cleanup;
	}

done:
	CoTaskMemFree(pbPublicKey);

	//////////////////////////////////////////////////////////////////////////////////////////





	//DEBUG//printf("MessageDigest : ");
	printAsHex(MessageDigest, MessageDigestLength);
	//DEBUG//printf("\n\n");

	//DEBUG//printf("Signature  : ");
	printAsHex(SignatureBlob, SignatureBlobLength);
	//DEBUG//printf("\n\n");

	BCRYPT_PKCS1_PADDING_INFO   PKCS1PaddingInfo = { 0 };
	switch (algo) {
	case MBEDTLS_MD_PKCS1_MD5_RSA:
	case MBEDTLS_MD_MD5:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_MD5_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA1_RSA:
	case MBEDTLS_MD_SHA1:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA256_RSA:
	case MBEDTLS_MD_SHA256:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA384_RSA:
	case MBEDTLS_MD_SHA384:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
		break;
	case MBEDTLS_MD_SHA512:
	case MBEDTLS_MD_PKCS1_SHA512_RSA:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
		break;

	case MBEDTLS_MD_PKCS1_SHA384_ECDSA:
		PKCS1PaddingInfo.pszAlgId = NCRYPT_ECDSA_P384_ALGORITHM;
		break;
	}
	if (KeyHandle != NULL) {
		Status = BCryptVerifySignature(
			KeyHandle,                  // Handle of the key used to decrypt the signature
			&PKCS1PaddingInfo,                       // Padding information
			(PUCHAR)MessageDigest,              // Hash of the message
			MessageDigestLength,        // Hash's length
			(PUCHAR)SignatureBlob,              // Signature - signed hash data
			SignatureBlobLength,        // Signature's length
			BCRYPT_PAD_PKCS1);                         // Flags
	}
	if (!NT_SUCCESS(Status))
	{
		//DEBUG//printf("BCryptVerifySignature Failed %x\n\n", Status);
		goto cleanup;
	}

	Status = 0;

cleanup:

	/*if (NULL != MessageDigest)
	{
		HeapFree(GetProcessHeap(), 0, MessageDigest);
		MessageDigest = NULL;
	}*/

	if (NULL != KeyHandle)
	{
		BCryptDestroyKey(KeyHandle);
		KeyHandle = NULL;
	}

	if (NULL != RsaAlgHandle)
	{
		BCryptCloseAlgorithmProvider(RsaAlgHandle, 0);
	}

	return Status;

}

