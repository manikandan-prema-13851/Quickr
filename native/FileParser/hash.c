#include "hash.h"
#include<bcrypt.h>

__declspec(noinline) int calculateHash(mbedtls_md_type_t algoType, char* buffer, size_t len, OUT char** digestOut, OUT int* digestOutLen) {
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	BCRYPT_HASH_HANDLE HashHandle = NULL;
	NTSTATUS status = -1;
	ULONG HashLength = 0;
	ULONG ResultLength = 0;

	LPCWSTR Algo;
	switch (algoType)
	{
	case MBEDTLS_MD_SHA1:
	case MBEDTLS_MD_PKCS1_SHA1_RSA:
		Algo = BCRYPT_SHA1_ALGORITHM;
		break;
	case MBEDTLS_MD_MD5:
	case MBEDTLS_MD_PKCS1_MD5_RSA:
		Algo = BCRYPT_MD5_ALGORITHM;
		break;
	case MBEDTLS_MD_SHA256:
	case MBEDTLS_MD_PKCS1_SHA256_RSA:
		Algo = BCRYPT_SHA256_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA384_RSA:
	case MBEDTLS_MD_SHA384:
		Algo = BCRYPT_SHA384_ALGORITHM;
		break;
	case MBEDTLS_MD_SHA512:
	case MBEDTLS_MD_PKCS1_SHA512_RSA:
		Algo = BCRYPT_SHA512_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA384_ECDSA:
		Algo = BCRYPT_ECDSA_P384_ALGORITHM;
		break;
	default:
		//printf("Unsupported Hash Algorithm used for PE hashing.\n\n");
		status = -1;
		goto cleanup;
	}
	status = BCryptOpenAlgorithmProvider(&AlgHandle, Algo, NULL, BCRYPT_HASH_REUSABLE_FLAG);
	if (!NT_SUCCESS(status))
	{
		//DEBUG//printf("unable to open algorithm handle \n");

		goto cleanup;
	}
	status = BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&HashLength, sizeof(HashLength), &ResultLength, 0);
	if (!NT_SUCCESS(status))
	{
		//DEBUG//printf("Unable to fetch hash length\n");

		goto cleanup;
	}
	*digestOut = (char*)calloc(HashLength, sizeof(char));
	if (*digestOut) {

	}
	else {
		*digestOut = NULL;
	}

	status = BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(status))
	{
		printf("unable to open hash handle \n");
		status = -1;
		goto cleanup;
	}

	status = BCryptHashData(HashHandle, buffer, (ULONG)len, 0);
	if (!NT_SUCCESS(status))
	{
		printf("calculateHash :: BCryptHashData Failed %x\n\n", status);
		status = -1;
		goto cleanup;
	}

	status = BCryptFinishHash(HashHandle, *digestOut, HashLength, 0);
	if (!NT_SUCCESS(status))
	{
		printf("Unable to finish hash %x\n", status);
		//return -1;
		status = -1;
		goto cleanup;
	}




	//UINT8* temp = *digestOut;
	//for (ULONG i = 0; i < HashLength; i++) {
		//printf("%02X ", (UINT8)temp[i]);
	//}
	//printf("\n\n");
	//memcpy();

	//for (int i = 0; *digestOut && i < strlen(*digestOut); i++)
	//{
	//
	//	printf("%02X ", (UINT8)(*digestOut)[i]);
	//}
	//printf("\n");

	* digestOutLen = HashLength;
	status = 0;
	if (HashHandle != NULL)
	{
		BCryptDestroyHash(HashHandle);
	}
	if (AlgHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}
	return status;

cleanup:
	if (*digestOut)
		free(*digestOut);
	*digestOut = NULL;
	*digestOutLen = 0;
	if (HashHandle != NULL)
	{
		BCryptDestroyHash(HashHandle);
	}
	if (AlgHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}
	return status;
}
