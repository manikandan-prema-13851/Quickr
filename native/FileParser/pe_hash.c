#include "pe_hash.h"
#include <errno.h>
#define errno   (*_errno())
#include "Header.h"
/*
 * Compare two sections for canonicalisation.
 */
__declspec(noinline) static int pefile_compare_shdrs(const void* a, const void* b)
{
	const struct section_header* shdra = a;
	const struct section_header* shdrb = b;
	int rc;

	if (shdra->data_addr > shdrb->data_addr)
		return 1;
	if (shdrb->data_addr > shdra->data_addr)
		return -1;

	if (shdra->virtual_address > shdrb->virtual_address)
		return 1;
	if (shdrb->virtual_address > shdra->virtual_address)
		return -1;

	rc = strcmp(shdra->name, shdrb->name);
	if (rc != 0)
		return rc;

	if (shdra->virtual_size > shdrb->virtual_size)
		return 1;
	if (shdrb->virtual_size > shdra->virtual_size)
		return -1;

	if (shdra->raw_data_size > shdrb->raw_data_size)
		return 1;
	if (shdrb->raw_data_size > shdra->raw_data_size)
		return -1;

	return 0;
}


__declspec(noinline)  NTSTATUS AddDataToCalculateHash(BCRYPT_HASH_HANDLE* HashHandle, FILE* fp, size_t start, size_t offset, struct PEImgDetails* data) {

	size_t Length = 1024 * 1024 * 8;
	char* buffer = calloc(Length, sizeof(char));
	if (buffer == NULL) {
		//DEBUG//printf("Error num to malloc %d\n", errno);
		goto exit;
	}

	size_t yetToRead = offset;
	size_t localStart = start;
	//DEBUG//printf("ToReadSize :  %d , LocalStart : %d and YetToRead : %d \n", offset, localStart, yetToRead);

	while (yetToRead > 0 && localStart <= start + offset)
	{
		size_t toReadSize = 0;
		if (yetToRead > Length ) {
			//DEBUG//printf("in\n\n");
			yetToRead = yetToRead - Length;
			toReadSize = Length;
		}
		else {
			toReadSize = yetToRead;
			yetToRead = 0;
		}

		//DEBUG//printf("ToReadSize :  %d , LocalStart : %p and YetToRead : %p and length : %d \n", toReadSize, localStart, yetToRead,Length);

		if (1 != freadW(buffer, localStart, toReadSize, 1, fp, data->fileSize)) {
		//if (1 != fpread(buffer, toReadSize, 1, localStart, fp)) {
			//DEBUG//printf("GLE %d\n", GetLastError());
			if (buffer)free(buffer);
			//continue;
			return -1;
			//break;
		}
		localStart = localStart + toReadSize;


		NTSTATUS status = BCryptHashData(*HashHandle, (PUCHAR)buffer,(ULONG) toReadSize, 0);
		if (!NT_SUCCESS(status))
		{
			if (buffer)free(buffer);
			return status;
		}



	}

	if (buffer)free(buffer);

	return 0;
exit:
	if (buffer)free(buffer);
	return -1;
}



/*
 * Load the contents of the PE binary into the digest, leaving out the image
 * checksum and the certificate data block.
 */
__declspec(noinline) int pefile_digest_pe_contents(FILE* fp, unsigned int pelen, struct pefile_context* ctx, BCRYPT_HASH_HANDLE* HashHandle, struct PEImgDetails* data)
{
	unsigned* canon, tmp, loop, i, hashed_bytes;
	int internal_hashed_bytes = 0;

	NTSTATUS status = AddDataToCalculateHash(HashHandle, fp, 0, ctx->image_checksum_offset, data);
	internal_hashed_bytes += ctx->image_checksum_offset;

	if (!NT_SUCCESS(status)) {
		return -1;
	}

	tmp = ctx->image_checksum_offset + sizeof(UINT32);
	status = AddDataToCalculateHash(HashHandle, fp, tmp, ctx->cert_dirent_offset - tmp, data);
	if (!NT_SUCCESS(status)) {
		return -1;
	}                                     

	// Initialize and allocate memory for canon
	canon = calloc(ctx->n_sections, sizeof(unsigned));
	if (!canon) {
		return -ENOMEM;
	}
	memset(canon, 0xFF, ctx->n_sections * sizeof(unsigned)); // Initialize to invalid values

	// Canonicalize the section table using insertion sort
	canon[0] = 0;
	for (loop = 1; loop < ctx->n_sections; loop++) {
		for (i = 0; i < loop; i++) {
			if (loop >= ctx->n_sections || i >= ctx->n_sections) { // Bounds check
				free(canon);
				return -1;
			}
			if (pefile_compare_shdrs(&ctx->secs[canon[i]], &ctx->secs[loop]) > 0) {
				memmove(&canon[i + 1], &canon[i], (loop - i) * sizeof(canon[0]));
				break;
			}
		}
		if (i < ctx->n_sections) {
			canon[i] = loop;
		}
		else {
			free(canon);
			return -1;
		}
	}

	// Validate sorted canon array
	for (unsigned int idx = 0; idx < ctx->n_sections; idx++) {
		if (canon[idx] < 0 || canon[idx] >= ctx->n_sections) {
			printf("Invalid canon[%d] = %d\n", idx, canon[idx]);
			free(canon);
			return -1;
		}
	}

	// Process sections in sorted order
	i = 0;
	for (loop = 0; loop < ctx->n_sections; loop++) {
		i = canon[loop];
		if (ctx->secs[i].raw_data_size == 0) {
			continue;
		}
		else {
			break;
		}
	}

	tmp = ctx->cert_dirent_offset + sizeof(struct data_dirent);
	if (canon[loop] < 0 || canon[loop] >= ctx->n_sections) {
		free(canon);
		return -1;
	}
	status = AddDataToCalculateHash(HashHandle, fp, tmp, ctx->secs[canon[loop]].data_addr - tmp, data);
	if (!NT_SUCCESS(status)) {
		free(canon);
		return -1;
	}

	hashed_bytes = ctx->secs[canon[loop]].data_addr;

	for (loop = 0; loop < ctx->n_sections; loop++) {
		i = canon[loop];
		if (ctx->secs[i].raw_data_size == 0) {
			continue;
		}
		status = AddDataToCalculateHash(HashHandle, fp, ctx->secs[i].data_addr, ctx->secs[i].raw_data_size, data);
		hashed_bytes += ctx->secs[i].raw_data_size;
		if (!NT_SUCCESS(status)) {
			free(canon);
			return -1;
		}
	}

	if (pelen > hashed_bytes) {
		tmp = hashed_bytes + ctx->certs_size;
		status = AddDataToCalculateHash(HashHandle, fp, hashed_bytes, pelen - tmp, data);
		if (!NT_SUCCESS(status)) {
			free(canon);
			return -1;
		}
	}
	free(canon);
	return 0;
}




/*
 * Digest the contents of the PE binary, leaving out the image checksum and the
 * certificate data block.
 */
__declspec(noinline) int pefile_digest_pe(FILE* fp, unsigned int pelen, struct pefile_context* ctx, mbedtls_md_type_t algoType, OUT char** digestOut, OUT int* digestOutLen, struct PEImgDetails* data)
{

	_Post_ _Notnull_ void* digest;
	int ret;
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	BCRYPT_HASH_HANDLE HashHandle = NULL;
	NTSTATUS status = -1;
	ULONG HashLength = 0;
	ULONG ResultLength = 0;

	LPCWSTR Algo;
	switch (algoType)
	{
	case MBEDTLS_MD_SHA256:
	case MBEDTLS_MD_PKCS1_SHA256_RSA:
		Algo = BCRYPT_SHA256_ALGORITHM;
		break;
	case MBEDTLS_MD_PKCS1_SHA1_RSA:
	case MBEDTLS_MD_SHA1:
		Algo = BCRYPT_SHA1_ALGORITHM;
		break;
	case MBEDTLS_MD_SHA384:
	case MBEDTLS_MD_PKCS1_SHA384_RSA:
		Algo = BCRYPT_SHA384_ALGORITHM;
		break;
	case MBEDTLS_MD_SHA512:
	case MBEDTLS_MD_PKCS1_SHA512_RSA:
		Algo = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		//DEBUG//printf("Unsupported Hash Algorithm used for PE hashing, Check with Developer.\n\n");
		return -1;
	}
	status = BCryptOpenAlgorithmProvider(&AlgHandle, Algo, NULL, BCRYPT_HASH_REUSABLE_FLAG);
	if (!NT_SUCCESS(status))
	{
		//DEBUG//printf("unable to open algorithm handle \n");
		return status;
	}
	status = BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&HashLength, sizeof(HashLength), &ResultLength, 0);
	if (!NT_SUCCESS(status))
	{
		//DEBUG//printf("Unable to fetch hash length\n");
		return status;
	}
	//DEBUG//printf("Length = %d\n", HashLength);


	status = BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(status))
	{
		//DEBUG//printf("unable to open hash handle \n");
		return -1;
	}




	ret = pefile_digest_pe_contents(fp, pelen, ctx, &HashHandle, data);
	if (ret < 0) {
		//printf("pefile_digest_pe_contents Failed!\n\n");
		return -1;
	}

	digest = calloc(HashLength, sizeof(char));
	if (digest != NULL) {
		status = BCryptFinishHash(HashHandle, digest, HashLength, 0);
	}
	else {
		return EXIT_FAILURE;
	}
	if (!NT_SUCCESS(status))
	{
		//printf("Unable to finish hash %x\n", status);
		if (digest) {
			free(digest);
			digest = NULL;
		}
		return -1;
	}

	if (HashHandle != NULL)
	{
		BCryptDestroyHash(HashHandle);
	}
	if (AlgHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}
	// testing 
	//unsigned char digestT[] = {
	//	0xBC, 0x43, 0xD6, 0x5C, 0xC4, 0x16, 0x70, 0xFB,
	//	0xB1, 0xE1, 0xA6, 0x86, 0xAE, 0x62, 0xBF, 0xF3,
	//	0xF9, 0xAA, 0x78, 0x5A
	//};
	//memcpy(digest, digestT, HashLength);
	// BC 43 D6 5C C4 16 70 FB B1 E1 A6 86 AE 62 BF F3 F9 AA 78 4A
	//3f 60 d1 33 59 5a ba b0 e8 8c f1 d5 98 15 ad b6 35 56 6a d1 77 02 37 59 c5 a5 c2 61 fc 98 e3 95
	//DEBUG//printf("Digest calc = [%*ph]\n", ctx->digest_len, digest);
	//UINT8* temp = digest;
	//printf("Original Details  \n");
	//for (int i = 0; i < HashLength; i++) {
	//	printf("%02X ", (UINT8)temp[i]);
	//}
	//printf("\n\n");

	*digestOut = digest;
	*digestOutLen = HashLength;
	return 0;
}


/*
 * Digest the contents of the PE binary, leaving out the image checksum and the
 * certificate data block.
 */
static const BYTE rgbMsg[] =
{
	0x61, 0x62, 0x63
};
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
// https://docs.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
