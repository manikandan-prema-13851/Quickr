#include "embeded.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include "fUtil.h"
// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")
struct IMAGE_RESOURCE_DIRECTORY {
	UINT32   Characteristics;
	UINT32   TimeDateStamp;
	UINT16    MajorVersion;
	UINT16    MinorVersion;
	UINT16    NumberOfNamedEntries;
	UINT16    NumberOfIdEntries;
	//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
};


struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
		struct {
			DWORD NameOffset : 31;
			DWORD NameIsString : 1;
		} DUMMYSTRUCTNAME;
		DWORD   Name;
		WORD    Id;
	} DUMMYUNIONNAME;
	union {
		DWORD   OffsetToData;
		struct {
			DWORD   OffsetToDirectory : 31;
			DWORD   DataIsDirectory : 1;
		} DUMMYSTRUCTNAME2;
	} DUMMYUNIONNAME2;
};


struct IMAGE_RESOURCE_DATA_ENTRY {
	UINT32   DataOffset;
	UINT32   Size;
	UINT32    CodePage;
	UINT32    Reserved;
};


CONST UCHAR SG_ProtoCoded[] = {
   0x30, 0x82,
};


CONST UCHAR SG_SignedData[] = {
   0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
};


void convertFilePath(char* originalPath, char* convertedPath) {
	int i, j = 0;
	int len = (int)strlen(originalPath);

	for (i = 0; i < len; i++) {
		if (originalPath[i] == '\\') {
			convertedPath[j++] = '\\'; // Add an extra backslash
			convertedPath[j++] = '\\'; // Add the second backslash
		}
		else {
			convertedPath[j++] = originalPath[i]; // Copy the character as is
		}
	}
	convertedPath[j] = '\0'; // Null-terminate the string
}

__declspec(noinline) BOOL MyCryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex, PVOID* pParam, DWORD* dwOutSize) {
	BOOL  bReturn = FALSE;
	DWORD dwSize = 0;
	if (!pParam)
	{
		return FALSE;
	}
	// Get size
	bReturn = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, NULL, &dwSize);
	if (!bReturn)
	{
		return FALSE;
	}
	// Alloc memory via size
	*pParam = (PVOID)LocalAlloc(LPTR, dwSize);
	if (!*pParam)
	{
		return FALSE;
	}
	// Get data to alloced memory
	bReturn = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, *pParam, &dwSize);

	if (!bReturn)
	{
		if (*pParam) LocalFree(*pParam);
		return FALSE;
	}
	if (dwOutSize)
	{
		*dwOutSize = dwSize;
	}
	return TRUE;
}


__declspec(noinline) BOOL SafeToReadNBytes(DWORD dwSize, DWORD dwStart, DWORD dwRequestSize) {
	return dwSize - dwStart >= dwRequestSize;
}


_declspec(noinline) BOOL GetNestedSignerInfo(CONST PSIGNDATA_HANDLE AuthSignData, GenericLL* NestedChain) {
	GenericLL* NestedChainEnd = NestedChain;

	BOOL        bSucceed = FALSE;
	BOOL        bReturn = FALSE;
	HCRYPTMSG   hNestedMsg = NULL;
	PBYTE       pbCurrData = NULL;
	PBYTE       pbNextData = NULL;
	DWORD       n = 0x00;
	DWORD       cbCurrData = 0x00;


	if (!AuthSignData->pSignerInfo)
	{
		printf("No value for AuthsignData %d\n", __LINE__);
		return FALSE;
	}

	// printf("4\n");
	 // Traverse and look for a nested signature.
	for (n = 0; n < AuthSignData->pSignerInfo->UnauthAttrs.cAttr; n++)
	{
		if (!lstrcmpA(AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
			szOID_NESTED_SIGNATURE))
		{
			break;
		}
	}
	// Cannot find a nested signature attribute.
	if (n >= AuthSignData->pSignerInfo->UnauthAttrs.cAttr)
	{
		//  printf("5\n");
		bSucceed = FALSE;
		/*__leave;*/
		//printf("Cannot find a nested signature attribute. \n");
		goto cleanup;
	}
	pbCurrData = AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData;
	// printf("pbCurrData [%x]", pbCurrData);
	cbCurrData = AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData;
	//  printf("pbCurrData [%x]", cbCurrData);
	hNestedMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		0,
		0,
		NULL,
		0
	);
	if (!hNestedMsg) // Fatal Error
	{
		bSucceed = FALSE;
		printf("Fatel Error \n");
		goto cleanup;
	}
	// Multiple nested signatures just add one attr in UnauthAttrs
	// list of the main signature pointing to the first nested si-
	// gnature. Every nested signature exists side by side in an 8
	// bytes aligned way. According to the size of major signature
	// parse the nested signatures one by one.
	while (pbCurrData > (BYTE*)AuthSignData->pSignerInfo &&
		pbCurrData < (BYTE*)AuthSignData->pSignerInfo + AuthSignData->dwObjSize)
	{
		SIGNDATA_HANDLE NestedHandle = { 0 };
		// NOTE: The size in 30 82 xx doesnt contain its own size.
		// HEAD:
		// 0000: 30 82 04 df                ; SEQUENCE (4df Bytes)
		// 0004:    06 09                   ; OBJECT_ID(9 Bytes)
		// 0006:    |  2a 86 48 86 f7 0d 01 07  02
		//          |     ; 1.2.840.113549.1.7.2 PKCS 7 SignedData
		if (memcmp(pbCurrData + 0, SG_ProtoCoded, sizeof(SG_ProtoCoded)) ||
			memcmp(pbCurrData + 6, SG_SignedData, sizeof(SG_SignedData)))
		{
			break;
		}
		// Big Endian -> Little Endian
		cbCurrData = XCH_WORD_LITEND(*(WORD*)(pbCurrData + 2)) + 4;
		pbNextData = pbCurrData;
		pbNextData += _8BYTE_ALIGN(cbCurrData, (ULONG_PTR)pbCurrData);
		bReturn = CryptMsgUpdate(hNestedMsg, pbCurrData, cbCurrData, TRUE);
		pbCurrData = pbNextData;
		if (!bReturn)
		{
			continue;
		}
		bReturn = MyCryptMsgGetParam(hNestedMsg, CMSG_SIGNER_INFO_PARAM,
			0,
			(PVOID*)&NestedHandle.pSignerInfo,
			&NestedHandle.dwObjSize
		);
		if (!bReturn)
		{
			continue;
		}
		NestedHandle.hCertStoreHandle = CertOpenStore(CERT_STORE_PROV_MSG,
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			0,
			0,
			hNestedMsg
		);
		bSucceed = TRUE;
		//NestedChain.push_back(NestedHandle);
		if (NestedChain) {
			//printf("	Insert End \n");

			insert_end(&NestedChainEnd, &NestedHandle, sizeof(SIGNDATA_HANDLE));
		}
		else {
			//printf("Insert Start \n");
			insertGenericLL(&NestedChain, &NestedHandle, sizeof(SIGNDATA_HANDLE));
			NestedChainEnd = NestedChain;
		}
	}

cleanup:
	if (hNestedMsg) CryptMsgClose(hNestedMsg);

	return bSucceed;
}

_declspec(noinline) BOOL GetAuthedAttribute(PCMSG_SIGNER_INFO pSignerInfo) {
	BOOL    bSucceed = FALSE;
	DWORD   dwObjSize = 0x00;
	DWORD   n = 0x00;

	// printf("6\n");
	__try
	{
		for (n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
		{
			if (!lstrcmpA(pSignerInfo->AuthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign))
			{
				bSucceed = TRUE;
				break;
			}
		}
	}
	__finally
	{
	}
	return bSucceed;
}

_declspec(noinline) BOOL GetCounterSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pTargetSigner) {
	BOOL    bSucceed = FALSE;
	BOOL    bReturn = FALSE;
	DWORD   dwObjSize = 0x00;
	DWORD   n = 0x00;

	// printf("7\n");
	if (!pSignerInfo || !pTargetSigner)
	{
		return FALSE;
	}
	__try
	{
		*pTargetSigner = NULL;
		for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
		{
			if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign))
			{
				break;
			}
		}
		if (n >= pSignerInfo->UnauthAttrs.cAttr)
		{
			bSucceed = FALSE;
			__leave;
		}
		bReturn = CryptDecodeObject(MY_ENCODING,
			CMS_SIGNER_INFO,
			pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
			pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
			0,
			NULL,
			&dwObjSize
		);
		if (!bReturn)
		{
			bSucceed = FALSE;
			__leave;
		}
		*pTargetSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwObjSize);
		if (!*pTargetSigner)
		{
			bSucceed = FALSE;
			__leave;
		}
		bReturn = CryptDecodeObject(MY_ENCODING,
			CMS_SIGNER_INFO,
			pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
			pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
			0,
			(PVOID)*pTargetSigner,
			&dwObjSize
		);
		if (!bReturn)
		{
			if (*pTargetSigner) LocalFree(*pTargetSigner);
			bSucceed = FALSE;
			__leave;
		}
		bSucceed = TRUE;
	}
	__finally
	{
	}
	return bSucceed;
}

_declspec(noinline) char* TimeToString(FILETIME* pftIn, SYSTEMTIME* pstIn) {
	SYSTEMTIME st = { 0 };
	char* szBuffer = (char*)calloc(256,sizeof(char)); // Dynamically allocate memory
	//char* szBuffer = NULL;

	if (!pstIn)
	{
		if (!pftIn)
		{
			return ("");
		}
		FileTimeToSystemTime(pftIn, &st);
		pstIn = &st;
	}

	if(szBuffer!=NULL){
		if (sprintf(szBuffer, "%04d/%02d/%02d %02d:%02d:%02d",
			pstIn->wYear,
			pstIn->wMonth,
			pstIn->wDay,
			pstIn->wHour,
			pstIn->wMinute,
			pstIn->wSecond
		) != -1)
		{
			return (char*)(szBuffer);
		}
		else {
			return (char*)"n/a";
		}
	}
	else {
		return (char*)"n/a";
	}
}


__declspec(noinline) void ParseDERType(BYTE bIn, INT* iType, INT* iClass) {
	*iType = bIn & 0x3F;
	*iClass = bIn >> 6;

}


__declspec(noinline) DWORD ReadNumberFromNBytes(PBYTE pbSignature, DWORD dwStart, DWORD dwRequestSize) {
	DWORD dwNumber = 0;
	for (DWORD i = 0; i < dwRequestSize; i++)
	{
		dwNumber = dwNumber * 0x100 + pbSignature[dwStart + i];
	}
	return dwNumber;
}


__declspec(noinline) BOOL ParseDERSize(PBYTE pbSignature, DWORD dwSize, DWORD* dwSizefound, DWORD* dwBytesParsed) {
	if (pbSignature[0] > 0x80 &&
		!SafeToReadNBytes(dwSize, 1, pbSignature[0] - 0x80))
	{
		return FALSE;
	}
	if (pbSignature[0] <= 0x80)
	{
		*dwSizefound = pbSignature[0];
		*dwBytesParsed = 1;
	}
	else
	{
		*dwSizefound = ReadNumberFromNBytes(pbSignature, 1, pbSignature[0] - 0x80);

		*dwBytesParsed = 1 + pbSignature[0] - 0x80;
		//printf("dwBytesParsed%x", dwBytesParsed);
	}
	return TRUE;
}


_declspec(noinline) BOOL ParseDERFindType(INT iTypeSearch, PBYTE pbSignature, DWORD dwSize, DWORD* dwPositionFound, DWORD* dwLengthFound, DWORD* dwPositionError, INT* iTypeError) {
	DWORD   dwPosition = 0;
	DWORD   dwSizeFound = 0;
	DWORD   dwBytesParsed = 0;
	INT     iType = 0;
	INT     iClass = 0;

	*iTypeError = -1;
	*dwPositionFound = 0;
	*dwLengthFound = 0;
	*dwPositionError = 0;
	if (NULL == pbSignature)
	{
		*iTypeError = -1;
		return FALSE;
	}
	while (dwSize > dwPosition)
	{
		int count = SafeToReadNBytes(dwSize, dwPosition, 2);
		//printf("count [%d]", count);
		if (!count)
		{
			*dwPositionError = dwPosition;
			*iTypeError = -2;
			return FALSE;
		}
		ParseDERType(pbSignature[dwPosition], &iType, &iClass);
		switch (iType)
		{
		case 0x05: // NULL
			dwPosition++;
			if (pbSignature[dwPosition] != 0x00)
			{
				*dwPositionError = dwPosition;
				*iTypeError = -4;
				return FALSE;
			}
			dwPosition++;
			break;

		case 0x06: // OID
			dwPosition++;
			//printf("dwPosition 06 %d[%d]\n", dwPosition, __LINE__);
			if (!SafeToReadNBytes(dwSize - dwPosition, 1, pbSignature[dwPosition]))
			{
				*dwPositionError = dwPosition;
				*iTypeError = -5;
				return FALSE;
			}
			dwPosition += 1 + pbSignature[dwPosition];
			break;

		case 0x00: // ?
		case 0x01: // boolean
		case 0x02: // integer
		case 0x03: // bit std::string
		case 0x04: // octec std::string
		case 0x0A: // enumerated
		case 0x0C: // UTF8string
		case 0x13: // printable std::string
		case 0x14: // T61 std::string
		case 0x16: // IA5String
		case 0x17: // UTC time
		case 0x18: // Generalized time
		case 0x1E: // BMPstring
			dwPosition++;
			//printf("dwPosition 0c %d[%d]\n", dwPosition, __LINE__);
			if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition,
				&dwSizeFound,
				&dwBytesParsed))
			{
				*dwPositionError = dwPosition;
				*iTypeError = -7;
				return FALSE;
			}
			dwPosition += dwBytesParsed;
			if (!SafeToReadNBytes(dwSize - dwPosition, 0, dwSizeFound))
			{
				*dwPositionError = dwPosition;
				*iTypeError = -8;
				return FALSE;
			}
			if (iTypeSearch == iType)
			{
				*dwPositionFound = dwPosition;
				*dwLengthFound = dwSizeFound;
				return TRUE;
			}
			dwPosition += dwSizeFound;
			break;

		case 0x20: // context specific
		case 0x21: // context specific
		case 0x23: // context specific
		case 0x24: // context specific
		case 0x30: // sequence
		case 0x31: // set
			dwPosition++;
			//printf("dwPosition 30 %X [%d]\n", dwPosition, __LINE__);
			if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition,
				&dwSizeFound,
				&dwBytesParsed))
			{
				*dwPositionError = dwPosition;
				*iTypeError = -9;
				return FALSE;
			}
			dwPosition += dwBytesParsed;
			break;

		case 0x22: // ?
			//printf("dwPosition 22 %d[%d]\n", dwPosition, __LINE__);
			dwPosition += 2;
			break;

		default:
			*dwPositionError = dwPosition;
			*iTypeError = iType;
			return FALSE;
		}
	}
	return FALSE;
}

// Return A TimeStamp for the file CATALOG
_declspec(noinline) BOOL GetGeneralizedTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, char** TimeStamp) {
	BOOL        bSucceed = FALSE;
	BOOL        bReturn = FALSE;
	DWORD       dwPositionFound = 0;
	DWORD       dwLengthFound = 0;
	DWORD       dwPositionError = 0;
	DWORD       n = 0;
	INT         iTypeError = 0;
	SYSTEMTIME  sst, lst;
	FILETIME    fft, lft;

	ULONG wYear = 0;
	ULONG wMonth = 0;
	ULONG wDay = 0;
	ULONG wHour = 0;
	ULONG wMinute = 0;
	ULONG wSecond = 0;
	ULONG wMilliseconds = 0;




	for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
	{
		//printf("pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId %s\n", pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId);
		if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign))
		{
			break;
		}
	}

	//printf("szOID count %d \n", n);
	if (n >= pSignerInfo->UnauthAttrs.cAttr)
	{
		//printf("Failed for n >= pSignerInfo->UnauthAttrs.cAttr \n");
		return FALSE;
	}

	else {

	}


	bReturn = ParseDERFindType(0x04,
		pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
		pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
		&dwPositionFound,
		&dwLengthFound,
		&dwPositionError,
		&iTypeError
	);
	if (!bReturn)
	{
		//printf("return in PaserDERFindType1s \n");

		return FALSE;
	}
	//printf("dwPositionFound %d\n", dwPositionFound);
	PBYTE pbOctetString = &pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData[dwPositionFound];
	//printf("pbOctetString %s\n", pbOctetString);
	bReturn = ParseDERFindType(0x18, pbOctetString, dwLengthFound,
		&dwPositionFound,
		&dwLengthFound,
		&dwPositionError,
		&iTypeError
	);
	if (!bReturn)
	{
		printf("return in PaserDERFindType \n");
		return FALSE;
	}


	CHAR szBuffer[256];
	strncpy(szBuffer, (CHAR*)&(pbOctetString[dwPositionFound]), dwLengthFound);
	//strcpy(szBuffer, (char*)&pbOctetString[dwPositionFound]);
	szBuffer[dwLengthFound] = 0;
	_snscanf_s(szBuffer, 256, "%04d%02d%02d%02d%02d%02d.%03dZ",
		&wYear,
		&wMonth,
		&wDay,
		&wHour,
		&wMinute,
		&wSecond,
		&wMilliseconds
	);

	sst.wYear = (WORD)wYear;
	sst.wMonth = (WORD)wMonth;
	sst.wDay = (WORD)wDay;
	sst.wHour = (WORD)wHour;
	sst.wMinute = (WORD)wMinute;
	sst.wSecond = (WORD)wSecond;
	sst.wMilliseconds = (WORD)wMilliseconds;

	SystemTimeToFileTime(&sst, &fft);

	FileTimeToLocalFileTime(&fft, &lft);

	FileTimeToSystemTime(&lft, &lst);

	char* timeStampDupValue = TimeToString(NULL, &lst);

	strDataCopy(TimeStamp, timeStampDupValue);

	if (timeStampDupValue) {
		free(timeStampDupValue);
	}

	return TRUE;
}

_declspec(noinline) BOOL CalculateDigestAlgorithm(LPCSTR pszObjId, char** Algorithm) {
	if (!pszObjId)
	{
		*Algorithm = "Unknown";
	}
	else if (!strcmp(pszObjId, szOID_OIWSEC_sha1))
	{
		*Algorithm = "SHA1";
	}
	else if (!strcmp(pszObjId, szOID_RSA_MD5))
	{
		*Algorithm = "MD5";
	}
	else if (!strcmp(pszObjId, szOID_NIST_sha256))
	{
		*Algorithm = "SHA256";
	}
	else
	{
		*Algorithm = (LPSTR)pszObjId;
	}
	char* AlgorithmDup = StripString(*Algorithm);

	strDataCopy(Algorithm, AlgorithmDup);

	//printf("Algorithm %s\n", *Algorithm);

	return TRUE;
}

_declspec(noinline) BOOL CalculateSignVersion(DWORD dwVersion, char** Version) {
	switch (dwVersion)
	{
	case CERT_V1:
		*Version = "V1";
		break;
	case CERT_V2:
		*Version = "V2";
		break;
	case CERT_V3:
		*Version = "V3";
		break;
	default:
		*Version = "Unknown";
		break;
	}
	char* versionDup = StripString(*Version);

	strDataCopy(Version, versionDup);

	//printf("version %s\n\n", *Version);
	return TRUE;
}

_declspec(noinline) BOOL CalculateHashOfBytes(BYTE* pbBinary, ALG_ID Algid, DWORD dwBinary, char** Hash) {
	BOOL        bReturn = FALSE;
	DWORD       dwLastError = 0;
	HCRYPTPROV  hProv = 0;
	HCRYPTHASH  hHash = 0;
	DWORD       cbHash = 0;
	BYTE        rgbHash[SHA1LEN] = { 0 };
	CHAR        hexbyte[3] = { 0 };
	CONST CHAR  rgbDigits[] = "0123456789abcdef";
	char CalcHash[100] = { 0 };

	bReturn = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!bReturn)
	{
		dwLastError = GetLastError();
		return FALSE;
	}
	// printf("%d [%d]\n", Algid, __LINE__);
	bReturn = CryptCreateHash(hProv, Algid, 0, 0, &hHash);
	if (!bReturn)
	{
		dwLastError = GetLastError();
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	bReturn = CryptHashData(hHash, pbBinary, dwBinary, 0);
	if (!bReturn)
	{
		dwLastError = GetLastError();
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	if (CALG_SHA1 == Algid)
	{
		cbHash = SHA1LEN;
	}
	else if (CALG_MD5 == Algid)
	{
		cbHash = MD5LE;
	}
	else
	{
		cbHash = 0;
	}
	hexbyte[2] = '\0';
	bReturn = CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);
	if (!bReturn)
	{
		dwLastError = GetLastError();
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	for (DWORD i = 0; i < cbHash; i++)
	{
		hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
		hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
		//CalcHash.append(hexbyte);
		CalcHash[i * 2] = hexbyte[0];
		CalcHash[i * 2 + 1] = hexbyte[1];
	}
	*Hash = (char*)calloc(((size_t)cbHash * 2) + 1, sizeof(char));

	if (*Hash) {

		//memset(*Hash, 0, ((size_t)cbHash * 2 + 1));
		strncpy(*Hash, CalcHash, (((size_t)cbHash * 2)) + 1);
	}


	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return TRUE;
}

_declspec(noinline) BOOL CalculateCertAlgorithm(LPCSTR pszObjId, char** Algorithm) {
	if (!pszObjId)
	{
		*Algorithm = "Unknown";
	}
	else if (0 == strcmp(pszObjId, szOID_RSA_SHA1RSA))
	{
		*Algorithm = "sha1RSA(RSA)";
	}
	else if (0 == strcmp(pszObjId, szOID_OIWSEC_sha1RSASign))
	{
		*Algorithm = "sha1RSA(OIW)";
	}
	else if (0 == strcmp(pszObjId, szOID_RSA_MD5RSA))
	{
		*Algorithm = "md5RSA(RSA)";
	}
	else if (0 == strcmp(pszObjId, szOID_OIWSEC_md5RSA))
	{
		*Algorithm = "md5RSA(OIW)";
	}
	else if (0 == strcmp(pszObjId, szOID_RSA_MD2RSA))
	{
		*Algorithm = "md2RSA(RSA)";
	}
	else if (0 == strcmp(pszObjId, szOID_RSA_SHA256RSA))
	{
		*Algorithm = "sha256RSA(RSA)";
	}
	else if (0 == strcmp(pszObjId, szOID_RSA_SHA384RSA))
	{
		*Algorithm = "sha356RSA(RSA)";
	}
	else
	{
		*Algorithm = (char*)pszObjId;
	}
	char* AlgorithmDUP = StripString(*Algorithm);

	strDataCopy(Algorithm, AlgorithmDUP);

	return TRUE;
}

/// <summary>
/// get data
/// </summary>
/// <param name="pszObjId"></param>
/// <param name="Algorithm"></param>
/// <returns></returns>
_declspec(noinline) BOOL CalculateSignSerial(BYTE* pbData, DWORD cbData, char** Serial) {
	BOOL    bReturn = FALSE;
	DWORD   dwSize = 0x400;
	BYTE    abSerial[0x400] = { 0 };
	CHAR    NameBuff[0x400] = { 0 };

	//Serial.clear();
	*Serial = " ";
	for (UINT uiIter = 0; uiIter < cbData && uiIter < 0x400; uiIter++)
	{
		abSerial[uiIter] = pbData[cbData - 1 - uiIter];
	}
	bReturn = CryptBinaryToStringA(abSerial, cbData, CRYPT_STRING_HEX, NameBuff, &dwSize);
	if (!bReturn)
	{
		return FALSE;
	}
	DWORD dwIter1 = 0;
	DWORD dwIter2 = 0;
	for (dwIter1 = 0; dwIter1 < dwSize; dwIter1++)
	{
		if (!isspace(NameBuff[dwIter1]))
		{
			NameBuff[dwIter2++] = NameBuff[dwIter1];
		}
	}
	NameBuff[dwIter2] = '\0';
	*Serial = (char*)(NameBuff);
	char* SerialDUP = StripString(*Serial);

	strDataCopy(Serial, SerialDUP);


	return TRUE;
}

_declspec(noinline) BOOL GetStringFromCertContext(PCCERT_CONTEXT pCertContext, DWORD Type, DWORD Flag, char** s) {
	DWORD dwData = 0x00;
	LPSTR pszTempName = NULL;

	dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, NULL, 0);
	if (!dwData)
	{
		CertFreeCertificateContext(pCertContext);
		return FALSE;
	}
	pszTempName = (LPSTR)LocalAlloc(LPTR, dwData * sizeof(CHAR));
	if (!pszTempName)
	{
		CertFreeCertificateContext(pCertContext);
		return FALSE;
	}
	dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, pszTempName, dwData);
	if (!dwData)
	{
		LocalFree(pszTempName);
		return FALSE;
	}

	strDataCopy(s, pszTempName);

	*s = StripString(*s);
	LocalFree(pszTempName);
	return TRUE;
}

_declspec(noinline) BOOL GetSignerSignatureInfo(HCERTSTORE hSystemStore, HCERTSTORE hCertStore, PCCERT_CONTEXT pOrigContext, PCCERT_CONTEXT* pCurrContext, SIGN_NODE_INFO* SignNode) {
	//CERT_CONTEXT* pCurrContext = &pCurr;
	BOOL            bReturn = FALSE;
	PCERT_INFO      pCertInfo = (*pCurrContext)->pCertInfo;
	LPCSTR          szObjId = NULL;
	CERT_NODE_INFO* CertNode = (CERT_NODE_INFO*)calloc(1, sizeof(CERT_NODE_INFO));
	//printf("************************************* GetSignerSignatureInfo *******************************\n\n");
	// Get certificate algorithm.
	szObjId = pCertInfo->SignatureAlgorithm.pszObjId;
	if (CertNode) {
		bReturn = CalculateCertAlgorithm(szObjId, &(CertNode->SignAlgorithm));
		// Get certificate serial.
		bReturn = CalculateSignSerial(pCertInfo->SerialNumber.pbData,
			pCertInfo->SerialNumber.cbData,
			&(CertNode->Serial)
		);

		// Get certificate version.
		bReturn = CalculateSignVersion(pCertInfo->dwVersion, &(CertNode->Version));

		// Get certficate subject.
		bReturn = GetStringFromCertContext((*pCurrContext),
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			&(CertNode->SubjectName)
		);

		// Get certificate issuer.
		bReturn = GetStringFromCertContext((*pCurrContext),
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			&(CertNode->IssuerName)
		);

		// Get certificate thumbprint.
		bReturn = CalculateHashOfBytes((*pCurrContext)->pbCertEncoded,
			CALG_SHA1,
			(*pCurrContext)->cbCertEncoded,
			&(CertNode->Thumbprint)
		);
	}
	// Get certificate CRL point.
	//bReturn = CalculateCertCRLpoint(pCertInfo->cExtension,
	//	pCertInfo->rgExtension,
	//	&CertNode.CRLpoint
	//);

	// Get certificate validity.
	char* TimeStampCpy = TimeToString(&pCertInfo->NotBefore, NULL);

	if (CertNode)
		strDataCopy(&CertNode->NotBefore, TimeStampCpy);
	//TimeStampCpy
	if (TimeStampCpy) {
		free(TimeStampCpy);
		TimeStampCpy = NULL;
	}

	TimeStampCpy = TimeToString(&pCertInfo->NotAfter, NULL);

	if (CertNode)
		strDataCopy(&CertNode->NotAfter, TimeStampCpy);
	if (TimeStampCpy) {
		free(TimeStampCpy);
		TimeStampCpy = NULL;
	}


	//SignNode->CertChain.push_back(CertNode);
	GenericLL* certChainStart = SignNode->CertChain;
	insertGenericLL(&certChainStart, CertNode, sizeof(CERT_NODE_INFO));
	SignNode->CertChain = certChainStart;

	//CERT_NODE_INFO* valueCheck = (CERT_NODE_INFO*)SignNode->CertChain->data;
	if (CertNode)
		free(CertNode);


	* pCurrContext = CertFindCertificateInStore(hCertStore,
		MY_ENCODING,
		0,
		CERT_FIND_SUBJECT_NAME,
		(PVOID)&pCertInfo->Issuer,
		NULL
	);
	// Root certificate is always included pe file certstore,
	// We can find it in system certstore.
	if (!(*pCurrContext))
	{
		*pCurrContext = CertFindCertificateInStore(hSystemStore,
			MY_ENCODING,
			0,
			CERT_FIND_SUBJECT_NAME,
			(PVOID)&pCertInfo->Issuer,
			NULL
		);
	}
	if (!(*pCurrContext))
	{
		return FALSE;
	}

	// Sometimes issuer is equal to subject. Jump out if so.

	CERT_PUBLIC_KEY_INFO CERT_PUBLIC_KEY = (*pCurrContext)->pCertInfo->SubjectPublicKeyInfo;
	return CertComparePublicKeyInfo(MY_ENCODING,
		&CERT_PUBLIC_KEY,
		&pOrigContext->pCertInfo->SubjectPublicKeyInfo
	) == FALSE;
}
// INFO: Old API print originalFileName only
//https://stackoverflow.com/questions/12396665/c-library-to-read-exe-version-from-linux
__declspec(noinline) int PrintVersion_File(const char* version, int offs, int maxLen, struct PEImgDetails* fdata) {
	offs = PAD(offs);
	WORD len = READ_WORD(version + offs);
	offs += 2;
	WORD valLen = READ_WORD(version + offs);
	offs += 2;
	WORD type = READ_WORD(version + offs);
	offs += 2;

	if (len > maxLen || valLen > maxLen) {
		return maxLen;
	}

	if (type == 0) {
		offs += (int)((wcslen((wchar_t*)(version + offs)) + 1) * 2); // Add null char and 2 bytes each since it's wide
		offs = PAD(offs);
		offs += valLen;
	}
	else if (type == 1) {
		wchar_t* key = (wchar_t*)(version + offs);
		char keyC[100];
		wcstombs(keyC, key, sizeof(keyC) - 1);
		keyC[sizeof(keyC) - 1] = '\0'; // Ensure null termination
		offs +=(int) ((wcslen(key) + 1) * 2);
		offs = PAD(offs);
		wchar_t* value = (wchar_t*)(version + offs);
		char valueC[1000];
		wcstombs(valueC, value, sizeof(valueC) - 1);
		valueC[sizeof(valueC) - 1] = '\0'; // Ensure null termination

		size_t valueCLen = strlen(valueC) + 1;
		if (strcmp(keyC, "CompanyName") == 0) {
			if (fdata->company != NULL) {
				free(fdata->company);
			}
			strDataNCopy(&fdata->company, valueC, valueCLen);
		}
		else if (strcmp(keyC, "FileDescription") == 0) {
			if (fdata->fileDescription != NULL) {
				free(fdata->fileDescription);
			}
			strDataNCopy(&fdata->fileDescription, valueC, valueCLen);
		}
		else if (strcmp(keyC, "FileVersion") == 0) {
			if (fdata->fileVersion != NULL) {
				free(fdata->fileVersion);
			}
			strDataNCopy(&fdata->fileVersion, valueC, valueCLen);
		}
		else if (strcmp(keyC, "InternalName") == 0) {
			if (fdata->internalName != NULL) {
				free(fdata->internalName);
			}
			strDataNCopy(&fdata->internalName, valueC, valueCLen);
		}
		else if (strcmp(keyC, "LegalCopyright") == 0) {
			if (fdata->copyRights != NULL) {
				free(fdata->copyRights);
			}
			strDataNCopy(&fdata->copyRights, valueC, valueCLen);
		}
		else if (strcmp(keyC, "OriginalFilename") == 0) {
			if (fdata->orgFileName != NULL) {
				free(fdata->orgFileName);
			}
			strDataNCopy(&fdata->orgFileName, valueC, valueCLen);
		}
		else if (strcmp(keyC, "ProductName") == 0) {
			if (fdata->product != NULL) {
				free(fdata->product);
			}
			strDataNCopy(&fdata->product, valueC, valueCLen);
		}
		else if (strcmp(keyC, "ProductVersion") == 0) {
			if (fdata->productVersion != NULL) {
				free(fdata->productVersion);
			}
			strDataNCopy(&fdata->productVersion, valueC, valueCLen);
		}

		offs += valLen * 2;
	}
	else {
		offs = maxLen; // Set offs to maxlen for exit
	}

	while (offs < len) {
		offs = PrintVersion_File(version, offs, maxLen, fdata);
	}

	return PAD(offs);
}
__declspec(noinline) static void* parse_resourcedata(const FILE* fp, int rsrcOffset, struct IMAGE_RESOURCE_DIRECTORY_ENTRY* resentry, struct PEImgDetails* data) {
	if (!resentry->DataIsDirectory) {
		struct IMAGE_RESOURCE_DATA_ENTRY* resdataentry = calloc(1, sizeof(struct IMAGE_RESOURCE_DATA_ENTRY));
		if (!resdataentry) return NULL;
		if (1 != freadW(resdataentry, (size_t)rsrcOffset + (size_t)resentry->OffsetToData, sizeof(struct IMAGE_RESOURCE_DATA_ENTRY), 1, (LPVOID)fp, data->fileSize)) {
			return NULL;
		}
		// if (1 != fpread(resdataentry, sizeof(struct IMAGE_RESOURCE_DATA_ENTRY), 1, (size_t)rsrcOffset + (size_t)resentry->OffsetToData, fp))return NULL;
		return resdataentry;
	}
	else {
		int cursor = rsrcOffset + resentry->OffsetToDirectory;
		struct IMAGE_RESOURCE_DIRECTORY* resdir = calloc(1, sizeof(struct IMAGE_RESOURCE_DIRECTORY));

		if (!resdir) return NULL;
		if(1!=freadW(resdir, cursor,sizeof(struct IMAGE_RESOURCE_DIRECTORY), 1, (LPVOID)fp, data->fileSize)){
			return NULL;
		}
		// if (1 != fpread(resdir, sizeof(struct IMAGE_RESOURCE_DIRECTORY), 1, cursor, fp))return NULL;

		cursor = cursor + sizeof(struct IMAGE_RESOURCE_DIRECTORY);

		struct IMAGE_RESOURCE_DIRECTORY_ENTRY* resdirentry = calloc(sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY), ((size_t)resdir->NumberOfNamedEntries + (int)resdir->NumberOfIdEntries));

		if (!resdirentry) return NULL;
		if(1 != freadW(resdirentry, cursor,sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * ((size_t)resdir->NumberOfNamedEntries + (int)resdir->NumberOfIdEntries), 1, (LPVOID)fp, data->fileSize )){
			return NULL;
		}
		// if (1 != fpread(resdirentry, sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * ((size_t)resdir->NumberOfNamedEntries + (int)resdir->NumberOfIdEntries), 1, cursor, fp))return NULL;
		for (int i = 0; i < (resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries); i++) {
			void* resdataentry = parse_resourcedata(fp, rsrcOffset, &resdirentry[i], data);
			if (resdataentry) {
				if (resdir)
					free(resdir);
				if (resdirentry)
					free(resdirentry);
				return resdataentry;
			}
		}
		if (resdir) {

			free(resdir);
		}
		if (resdirentry) {

			free(resdirentry);
		}
		return NULL;
	}
}


_declspec(noinline)  int parse_originalfilename_File(const HANDLE fp, unsigned int pelen, struct pefile_context* ctx, char** OriginalFileName, struct PEImgDetails* fdata) {
	struct IMAGE_RESOURCE_DIRECTORY* resdir = NULL;
	struct IMAGE_RESOURCE_DIRECTORY_ENTRY* resdirentry = NULL;
	struct IMAGE_RESOURCE_DATA_ENTRY* resdataentry = NULL;
	size_t cursor;
	int rsrcIndex = -1, ret = -1;
	struct section_header* secs = (struct section_header*)ctx->secs;
	char* versionstr = NULL;
	if (ctx->secs == NULL)
		return -1;
	for (unsigned int i = 0; i < ctx->n_sections; i++) {

		if (strcmp(secs[i].name, ".rsrc") == 0) {
			rsrcIndex = i;
		}
		//printf("%p,  %s \n", secs[i].virtual_address, secs[i].name);	
	}
	//printf("Rsrc index : %d \n", rsrcIndex);	
	if (rsrcIndex < 0) {
		//printf("Cannot find rsrc index\n");		
		return -1;
	}
	//Formula for calculating offset for ResorceEntry :  (RVAResourceTable � .section[.rsrc][VirtualAddress]) + .section[.rsrc][PointerToRawData]	
	//link : https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/	
	//printf("Virtual Addr of RES : %p\n", (ctx->resource_viirtualaddr - secs[rsrcIndex].virtual_address) + secs[rsrcIndex].data_addr);	
	resdir = (struct IMAGE_RESOURCE_DIRECTORY*)calloc(1, sizeof(struct IMAGE_RESOURCE_DIRECTORY));
	//resdir = ExAllocatePoolWithTag(NonPagedPool, (sizeof(struct IMAGE_RESOURCE_DIRECTORY)), AUTHCODE_VERIFIER_DRIVER_TAG);	
	cursor = ((size_t)ctx->resource_viirtualaddr - secs[rsrcIndex].virtual_address) + secs[rsrcIndex].data_addr;
	size_t rsrcOffset = cursor;
	//printf("rsrcOffset  %d \n", rsrcOffset);	
	if (!resdir) return -1;
	if(1!= freadW(resdir, cursor, sizeof(struct IMAGE_RESOURCE_DIRECTORY), 1, fp, fdata->fileSize)){
	// if (1 != fpread(resdir, sizeof(struct IMAGE_RESOURCE_DIRECTORY), 1, cursor, fp))
	// {
		//printf("Cannot read resource dir\n");
		ret = -1;
		goto cleanup;
	}
	//printf("Total Number of ResourceEntries top level : %d %d %d\n", resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries, sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY), sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * (resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries));	
	cursor = cursor + sizeof(struct IMAGE_RESOURCE_DIRECTORY);
	resdirentry = (struct IMAGE_RESOURCE_DIRECTORY_ENTRY*)calloc(((size_t)resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries), sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY));
	//resdirentry = ExAllocatePoolWithTag(NonPagedPool, (sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * (resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries)), AUTHCODE_VERIFIER_DRIVER_TAG);	
	//malloc(sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * (resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries));	
	if (!resdirentry) {
		ret = -1;
		goto cleanup;
	}
	if(1 != freadW(resdirentry, cursor, sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * ((size_t)resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries), 1, fp, fdata->fileSize)){
	// if (1 != fpread(resdirentry, sizeof(struct IMAGE_RESOURCE_DIRECTORY_ENTRY) * ((size_t)resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries), 1, cursor, fp)) {
		ret = -1;
		goto cleanup;
	}
	for (int i = 0; i < (resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries); i++) {
		if (resdirentry[i].Id == 16) {	//https://docs.microsoft.com/en-us/windows/win32/menurc/resource-definition-statements 16 is VERSION_RESOURCE	
			//printf("VersionInfo available %p\n", resdirentry[i].OffsetToDirectory + rsrcOffset);	
			resdataentry = (parse_resourcedata(fp, (int)rsrcOffset, &resdirentry[i], fdata));
			//printf("sf sf %d\n", resdataentry);	
			//printf(" Version Offset : %p %d\n", resdataentry->DataOffset, resdataentry->Size);	
			//if (resdataentry == NULL) goto cleanup;
			if (resdataentry) {
				//versionstr = ExAllocatePoolWithTag(NonPagedPool, (resdataentry->Size), AUTHCODE_VERIFIER_DRIVER_TAG);	
				//versionstr = (char*)calloc(1,(resdataentry->Size));	
				versionstr = calloc(resdataentry->Size, sizeof(char));
				if (!versionstr) {
					printf("mem not created !!");
					return -1;
				}
				if(1 != freadW(versionstr,((size_t)resdataentry->DataOffset - secs[rsrcIndex].virtual_address) + secs[rsrcIndex].data_addr, resdataentry->Size, 1, fp, fdata->fileSize)) {
				// if (1 != fpread(versionstr, resdataentry->Size, 1, ((size_t)resdataentry->DataOffset - secs[rsrcIndex].virtual_address) + secs[rsrcIndex].data_addr, fp, fdata->fileSize)) {
					ret = -1;
					goto cleanup;
				}
				struct VS_VERSIONINFO* vs = (struct VS_VERSIONINFO*)versionstr;
				PrintVersion_File(versionstr, 0, resdataentry->Size, fdata);
			}
			ret = 0;
			goto cleanup;
		}
		if (versionstr) {
			versionstr = NULL;
		}
	}
	ret = -1;
cleanup:
	if (resdir) {
		free(resdir);
	}
	if (resdirentry) {
		free(resdirentry);
	}
	if (versionstr) {
		free(versionstr);
	}
	if (resdataentry) {
		free(resdataentry);
	}
	return ret;
}

_declspec(noinline) BOOL  GetSignerCertificateInfo(LPCWSTR FileName, GenericLL** SignChain) {
	BOOL            bSucceed = FALSE;
	BOOL            bReturn = FALSE;
	HCERTSTORE      hSystemStore = NULL;
	SIGNDATA_HANDLE AuthSignData = { 0 };
	GenericLL* SignDataChainStart = NULL;
	GenericLL* SignDataChainEnd = NULL;
	GenericLL* SignChainEnd = NULL;

	if (*SignChain) {
		freeGenericLL(*SignChain);
		*SignChain = NULL;
	}

	// Open system certstore handle, in order to find root certificate.
	hSystemStore = CertOpenStore(
		(LPCSTR)CERT_STORE_PROV_SYSTEM, // Provider type
		MY_ENCODING,                   // Encoding type
		(HCRYPTPROV_LEGACY)NULL,       // Cast NULL to HCRYPTPROV_LEGACY
		CERT_SYSTEM_STORE_CURRENT_USER, // System store location
		L"Root"                        // Store name
	);
	if (!hSystemStore)
	{
		INT error = GetLastError();
		return FALSE;
	}
	// Query file auth signature and cert store Object.
	HCRYPTMSG hAuthCryptMsg = NULL;
	DWORD dwEncoding = 0x00;
	bReturn = CryptQueryObject(CERT_QUERY_OBJECT_FILE, FileName,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		NULL,
		NULL,
		&AuthSignData.hCertStoreHandle,
		&hAuthCryptMsg,
		NULL
	);

	if (!bReturn)
	{
		INT error = GetLastError();
		CertCloseStore(hSystemStore, 0);
		return FALSE;
	}

	// Get signer information pointer.
	bReturn = MyCryptMsgGetParam(hAuthCryptMsg, CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID*)&AuthSignData.pSignerInfo,
		&AuthSignData.dwObjSize
	);
	CryptMsgClose(hAuthCryptMsg);
	hAuthCryptMsg = NULL;
	if (!bReturn)
	{
		INT error = GetLastError();
		CertCloseStore(AuthSignData.hCertStoreHandle, 0);
		CertCloseStore(hSystemStore, 0);
		return FALSE;
	}
	if (SignDataChainEnd) {
		insert_end(&SignDataChainEnd, &AuthSignData, sizeof(SIGNDATA_HANDLE));
	}
	else {
		insertGenericLL(&SignDataChainStart, &AuthSignData, sizeof(SIGNDATA_HANDLE));
		SignDataChainEnd = SignDataChainStart;
	}
	bReturn = GetNestedSignerInfo(&AuthSignData, SignDataChainStart);
	while (SignDataChainStart != NULL) {
		GenericLL* tmp = SignDataChainStart;
		PCCERT_CONTEXT      pOrigContext = NULL;
		PCCERT_CONTEXT pCurrContext = NULL;
		LPCSTR              szObjId = NULL;
		PCMSG_SIGNER_INFO   pCounterSigner = NULL;
		SIGN_NODE_INFO* SignNode = NULL;
		SIGNDATA_HANDLE* signDataValue = NULL;
		signDataValue = (SIGNDATA_HANDLE*)tmp->data;
		SignDataChainStart = SignDataChainStart->next;
		SignNode = (SIGN_NODE_INFO*)calloc(1, sizeof(SIGN_NODE_INFO));

		if (!SignNode) {
			bSucceed = FALSE;
			break;
		}
		SignNode->CounterSign.SignerName = NULL;
		SignNode->CounterSign.MailAddress = NULL;
		SignNode->CounterSign.TimeStamp = NULL;
		SignNode->CertChain = NULL;
		GetAuthedAttribute(signDataValue->pSignerInfo);
		GetCounterSignerInfo(signDataValue->pSignerInfo, &pCounterSigner);


		if (pCounterSigner)
		{
			//  printf("8\n");
			//bReturn = GetCounterSignerData(pCounterSigner, SignNode.CounterSign);
		}
		else
		{
			//SIGN_COUNTER_SIGN timeStampValue = { 0 };
			bReturn = GetGeneralizedTimeStamp(signDataValue->pSignerInfo,
				//&timeStampValue.TimeStamp
				&SignNode->CounterSign.TimeStamp
			);

		}
		// Get digest algorithm.
		szObjId = signDataValue->pSignerInfo->HashAlgorithm.pszObjId;
		//char* digestValue = NULL;
		bReturn = CalculateDigestAlgorithm(szObjId, &SignNode->DigestAlgorithm);

		// Get signature version.
		bReturn = CalculateSignVersion(signDataValue->pSignerInfo->dwVersion, &SignNode->Version);
		//printf("signDataValue->pSignerInfo->dwVersion %d\n", signDataValue->pSignerInfo->dwVersion);
		//printf("SignNode->version %s\n", SignNode->Version);

		// Find the first certificate Context information.
		pCurrContext = CertFindCertificateInStore(signDataValue->hCertStoreHandle,
			MY_ENCODING,
			0,
			CERT_FIND_ISSUER_NAME,
			(PVOID)&signDataValue->pSignerInfo->Issuer,
			NULL);
		bReturn = (pCurrContext != NULL);
		int countcbCert = 0;
		while (bReturn)
		{
			countcbCert++;
			//printf("\n\n\n");
			//printf("cbCertEncoded %d\n", pCurrContext->cbCertEncoded);
			//printf("dwCertEncodingType %d\n", pCurrContext->dwCertEncodingType);
			//printf("pbCertEncoded %d\n", pCurrContext->pbCertEncoded[0]);


			pOrigContext = pCurrContext;
			// Get every signer signature information.
			bReturn = GetSignerSignatureInfo(hSystemStore, signDataValue->hCertStoreHandle,
				pOrigContext,
				&pCurrContext,
				SignNode
			);
			//printf("Number of rotation count %d is %d \n", countcbCert, bReturn);
			CertFreeCertificateContext(pOrigContext);
		}
		//printf("countcbCert %d\n", countcbCert);

		/*	printf("************************************* WHILE *******************************\n\n");

			while (SignNode->CertChain != NULL) {
				GenericLL* tmp = SignNode->CertChain;
				SignNode->CertChain = SignNode->CertChain->next;
				CERT_NODE_INFO* tmpValue = (CERT_NODE_INFO*)tmp->data;
				printf("signAlgorithm %s\n", tmpValue->SignAlgorithm);
				printf("NotBefore  %s\n", tmpValue->NotBefore);
				printf("notafter  %s\n", tmpValue->NotAfter);
				printf("CRLpoint %ws\n", tmpValue->CRLpoint);
				printf("IssuerName  %s\n", tmpValue->IssuerName);
				printf("SubjectName  %s\n", tmpValue->SubjectName);
				printf("Thumbprint %s\n", tmpValue->Thumbprint);
				printf("\n\n");

			}

			printf("************************************* ENDWHILE *******************************\n\n");*/

		if (pCurrContext) CertFreeCertificateContext(pCurrContext);
		if (pCounterSigner) LocalFree(pCounterSigner);
		if (signDataValue->pSignerInfo) LocalFree(signDataValue->pSignerInfo);
		if (signDataValue->hCertStoreHandle) CertCloseStore(signDataValue->hCertStoreHandle, 0);
		bSucceed = TRUE;
		if (SignChainEnd) {
			insert_end(&SignChainEnd, SignNode, sizeof(SIGN_NODE_INFO));
		}
		else {
			insertGenericLL(SignChain, SignNode, sizeof(SIGN_NODE_INFO));
			SignChainEnd = *SignChain;
		}

		/*if (SignNode->CounterSign.TimeStamp)
			free(SignNode->CounterSign.TimeStamp);
		if (SignNode->DigestAlgorithm)
			free(SignNode->DigestAlgorithm);
		if (SignNode->Version)
			free(SignNode->Version);
		if (SignNode)
			free(SignNode);*/
		if (SignNode)
			free(SignNode);

		if (tmp->data)
			free(tmp->data);
		if (tmp)
			free(tmp);

		//printf("	delete end\n");
		//SignDataChainStart = SignDataChainStart->next;

	}

	if (SignDataChainStart) {
		if (SignDataChainStart->data) {
			free(SignDataChainStart->data);
		}
		free(SignDataChainStart);
	}
	CertCloseStore(hSystemStore, 0);


	return bSucceed;
}



__declspec(noinline) BOOL MyCryptCalcFileHash(
	HANDLE FileHandle,
	PBYTE* szBuffer,
	DWORD* HashSize
) {
	BOOL bReturn = FALSE;
	if (!szBuffer || !HashSize)
	{
		return FALSE;
	}
	*HashSize = 0x00;
	// Get size.
	bReturn = CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, NULL, 0x00);
	// printf("Hash size %d\n", *HashSize);
	if (0 == *HashSize) // HashSize being zero means fatal error.
	{
		return FALSE;
	}
	*szBuffer = (PBYTE)calloc(*HashSize, 1);
	bReturn = CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, *szBuffer, 0x00);
	// printf("szBuffer  %s\n", *szBuffer);
	//printf("version info\n");
	// hdump((byte*)szBuffer, (size_t)HashSize, 0, 0);
	if (!bReturn)
	{
		free(*szBuffer);
	}
	return bReturn;
}

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile, struct PEImgDetails* pdata)
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	/*
	WVTPolicyGUID specifies the policy to apply on the file
	WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

	1) The certificate used to sign the file chains up to a root
	certificate located in the trusted root certificate store. This
	implies that the identity of the publisher has been verified by
	a certification authority.

	2) In cases where user interface is displayed (which this example
	does not do), WinVerifyTrust will check for whether the
	end entity certificate is stored in the trusted publisher store,
	implying that the user trusts content from this publisher.

	3) The end entity certificate has sufficient permission to sign
	code, as indicated by the presence of a code signing EKU or no
	EKU.
	*/

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		pdata->verified = 1;
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
				"Yes" when asked to install and run the signed
				subject.
		*/
		//wprintf_s(L"The file \"%s\" is signed and the signature "
		//	L"was verified.\n",
			//pwszSourceFile);
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			//wprintf_s(L"The file \"%s\" is not signed.\n",
				//pwszSourceFile);
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
	/*		wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				pwszSourceFile);*/
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
	/*	wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");*/
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
	/*	wprintf_s(L"The signature is present, but not "
			L"trusted.\n");*/
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		//wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
		//	L"representing the subject or the publisher wasn't "
		//	L"explicitly trusted by the admin and admin policy "
		//	L"has disabled user trust. No signature, publisher "
		//	L"or timestamp errors.\n");
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		//wprintf_s(L"Error is: 0x%x.\n",
			//lStatus);
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	return true;
}

int chkaddr_func(size_t base, size_t x, size_t s, size_t datalen) {
	if (x < base || s >= datalen || x > datalen - s) {
		return ELIBBAD;
	}
	return 0;
}

// Function to print content of a structure
void print_content(const unsigned char* data, size_t length) {
	printf("Content (%zu bytes): ", length);
	for (size_t i = 0; i < length; ++i) {
		printf("%02X ", data[i]);
	}
	printf("\n");
}


void decode_utctime(const unsigned char* buffer, size_t length, struct PEImgDetails* peSignInfo) {
	if (length != 13 || buffer[length - 1] != 'Z') {
		printf("Invalid UTCTime format\n");
		return;
	}

	char year[5] = "20";
	char month[3];
	char day[3];
	char hour[3];
	char minute[3];
	char second[3];

	strncpy(year + 2, (const char*)buffer, 2);
	year[4] = '\0';

	strncpy(month, (const char*)(buffer + 2), 2);
	month[2] = '\0';

	strncpy(day, (const char*)(buffer + 4), 2);
	day[2] = '\0';

	strncpy(hour, (const char*)(buffer + 6), 2);
	hour[2] = '\0';

	strncpy(minute, (const char*)(buffer + 8), 2);
	minute[2] = '\0';

	strncpy(second, (const char*)(buffer + 10), 2);
	second[2] = '\0';

	char timestamp[25];
	sprintf(timestamp, "%s/%s/%s %s:%s:%s UTC", year, month, day, hour, minute, second);
	strDataCopy(&peSignInfo->timeStamp, timestamp);
}

__declspec(noinline) int parseContentInfo0(struct ExtractedSignedData* esd, struct ParsedContentInfo* pconInfo, struct PEImgDetails* peSignInfo) {
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
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OCTET_STRING, 6);
	if (ret < 0) {
		return ret;
	}

	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_UTC_TIME, 6);
	if (ret < 0) {
		return ret;
	}

	decode_utctime((const unsigned char*)buffer, lSize, peSignInfo);
	buffer = buffer + lSize;
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 6);
	if (ret < 0) {
		return ret;
	}

	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 6);
	if (ret < 0) {
		return ret;
	}

	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC, 1);
	if (ret < 0) {
		return ret;
	}


	//Now we got the Algo, so calculate hash of contentinfo now
	ret = calculateHash(pconInfo->PEHashAlgo, contInfoHashCalcPoint, contInfoHashCalcPointLen, &pconInfo->ContentInfoHashStr, &pconInfo->lenContentInfoHashStr);
	if (ret < 0) {
		//DEBUG//printf("Unable to calculate hash of ContentInfo\n\n");
		return ret;
	}


	printAsHex(pconInfo->ContentInfoHashStr, pconInfo->lenContentInfoHashStr);


	return 0;
}


__declspec(noinline) int readData(unsigned char* fileData, unsigned char* fileDataEnd, long fileSize, struct PEImgDetails* peSignInfo, Tree_t* TrustedCAtree) {
	int ret = 0;
	struct ExtractedSignedData esd;
	struct ParsedSignedData psd;

	ret = extractRawSignedData((const char*)fileData, fileSize, &esd);
	if (ret < 0) {
		//printf("Unable to extract PKCS#7 data\n\n");
		peSignInfo->errorCode = IS_ZOHO_BINARY_EXTRACT_RAW_SIGNED_DATA;
		ret = -1;
		return 1;
	}

	//Get the SignerInfo parsed  
	if (parseSignerInfo(&esd, &psd.ParsedSignerInfo) < 0) {
		//printf("Unable to parse SignerInfo\n\n");
		peSignInfo->errorCode = IS_ZOHO_BINARY_PARSE_SIGNER_INFO;
		ret = -1;
		return 1;
	}

	//1. CertInfo is signer // certification verified done here and chain certify match also done
	if (verifyCertficateData(&esd, &psd, TrustedCAtree) < 0) {
		peSignInfo->errorCode = IS_ZOHO_BINARY_VERIFY_CERTFICATE_DATA;
		//DEBUG//printf("Chain is Invalid, so stop continuing the checks\n");
		//calculateHash free when filed
		if (psd.ParsedSignerInfo.AuthAtrHashStr) {
			free(psd.ParsedSignerInfo.AuthAtrHashStr);
			psd.ParsedSignerInfo.lenAuthAtrHashStr = 0;
			psd.ParsedSignerInfo.AuthAtrHashStr = NULL;
		}
		//DEBUG//printf("Chain is Invalid, so stop continuing the checks\n");
		/*peSignInfo->errorCode = IS_ZOHO_BINARY_VERIFY_CERTFICATE_DATA;*/
		ret = -1;
		return 1;
	}
	psd.ParsedContentInfo.PEHashAlgo = psd.ParsedSignerInfo.ContentInfoHashAlgo;
	//2. Hash_pe_in_contentInfo === Hash_pe
	//Get ContentInfo parsed
	if (parseContentInfo0(&esd, &psd.ParsedContentInfo, peSignInfo) < 0) {
		peSignInfo->errorCode = IS_ZOHO_BINARY_PARSE_CONTENT_INFO;
		ret = -1;
		goto cleanup;
	}
	{
		// skip this pe hash verify for catlog files
		//Get PE Hash we don't need this we calculated already
		//ret = pefile_digest_pe(fp, lSize, ctx, psd.ParsedContentInfo.PEHashAlgo, &psd.digest, &psd.digestLen);
		//Now compare the PEHash calculated with PEHash embedded in contentinfo blob
		//if (psd.digestLen != psd.ParsedContentInfo.lenPEHashStr) {
		//	//DEBUG//printf("Calculated Digest does not match with embedded PE Digest :: Length not match\n\n");
		//	peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
		//	ret = -1;
		//	goto cleanup;
		//}
		//for (int i = 0; i < psd.digestLen; i++) {
		//	if (psd.digest[i] != psd.ParsedContentInfo.PEHashStr[i]) {
		//		//printf("Calculated Digest does not match with embedded PE Digest:: index  %d\n\n", i);
		//		peSignInfo->errorCode = IS_ZOHO_BINARY_PE_DIGEST_MISMATCH;
		//		ret = -1;
		//		goto cleanup;
		//	}
		//}
	}

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

	ret = VerifySignature(psd.ParsedSignerInfo.AuthAtrHashStr, psd.ParsedSignerInfo.lenAuthAtrHashStr, psd.ParsedSignerInfo.EncryptedDigest, psd.ParsedSignerInfo.lenEncryptedDigest, psd.ParsedCertInfo.SignerPublicKey, psd.ParsedCertInfo.lenSignerPublicKey, psd.ParsedCertInfo.SignerExponent, psd.ParsedSignerInfo.ContentInfoHashAlgo);
	if (ret < 0)
	{
		peSignInfo->errorCode = IS_ZOHO_BINARY_VERIFY_SIGN_FAILED;
		//DEBUG//printf("Verification Failed %x\n\n", ret);
		ret = -1;
		goto cleanup;
	}
	else {

		//char timestamp[25];
		//if (parseContentInfo0(&esd, &psd.ParsedContentInfo, timestamp) == 0) {
		//	// timestamp
		//	strDataCopy(&peSignInfo->timeStamp, timestamp);
		//}

		//struct PEImgDetails peSignInfo;
		////DEBUG//printf("Verification Success :) So, the hash of PE is in match with signer certificate\n\n\n");
	//peSignInfo->verified = 1;

	//printf("%d ==> %s \n %d = => %s \n", psd.ParsedCertInfo.SigerCert->NameLen,psd.ParsedCertInfo.SigerCert->Name,psd.ParsedCertInfo.SigerCert->ThumbprintLen,psd.ParsedCertInfo.SigerCert->Thumbprint);
	//sigCharArray(&psd.ParsedCertInfo.SigerCert->Name, psd.ParsedCertInfo.SigerCert->NameLen);
		persistCharArray(&psd.ParsedCertInfo.SigerCert->Name, psd.ParsedCertInfo.SigerCert->NameLen);
		//persistCharArray(&psd.ParsedCertInfo.SigerCert->Thumbprint, psd.ParsedCertInfo.SigerCert->ThumbprintLen);

		//persistCharArray(&psd.ParsedCertInfo., psd.ParsedCertInfo.SigerCert->NameLen);


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

		//std::cout << psd.ParsedContentInfo.ContentInfoHashStr;
		if (psd.ParsedCertInfo.SigerCert->ThumbprintLen == 20) {
			for (int i = 0; i < psd.ParsedCertInfo.SigerCert->ThumbprintLen; i++) {
				// Ensure count stays within bounds
				if (!(count < (sizeof(buffer1) / 2)))
					break;

				// Use a properly sized buffer for the hex conversion
				char a[3]; // 2 characters + null terminator
				sprintf((char*)&a, "%02X", (UINT8)(psd.ParsedCertInfo.SigerCert->Thumbprint)[i]);

				// Append the converted characters to buffer1
				buffer1[count * 2] = a[0];
				buffer1[count * 2 + 1] = a[1];

				count++;
			}
			buffer1[count * 2] = '\0'; // Null-terminate the string
			strDataCopy(&peSignInfo->thumbprint, buffer1);
		}

		peSignInfo->verified = 1;
	}


	struct Certificate* temp = NULL;
	if (psd.ParsedCertInfo.SigerCert->Name)
		free(psd.ParsedCertInfo.SigerCert->Name);
	cleanup:
	while (psd.ParsedCertInfo.SigerCert) {
		temp = psd.ParsedCertInfo.SigerCert;

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

	return 0;
}

__declspec(noinline) void verifyCatlogFileAndGetData(const wchar_t* filename, struct PEImgDetails* data, Tree_t* TrustedCAtree) {

	FILE* file = _wfopen(filename, L"rb");
	if (!file) {
		wprintf(L"Error opening file: %ls\n", filename);
		return;
	}

	// Determine the size of the file
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET); // Rewind to the start of the file
		// Allocate memory to hold the file contents
	unsigned char* fileData = (unsigned char*)malloc(fileSize);
	unsigned char* fileDataEnd = NULL;
	if (!fileData) {
		perror("Memory allocation failed");
		fclose(file);
		return;
	}

	// Read the file contents into the allocated memory
	size_t bytesRead = fread(fileData, 1, fileSize, file);
	if (bytesRead != fileSize) {
		perror("Error reading file");
		free(fileData);
		fclose(file);
		return;
	}
	fileDataEnd = fileData + fileSize;
	readData(fileData, fileDataEnd, fileSize, data, TrustedCAtree);
	free(fileData);
	// Close the file
	fclose(file);
}

_declspec(noinline) void fetchSignerDetailsFromFile(LPCWSTR FilePath,struct PEImgDetails* data) {
	GenericLL* SignChain = NULL;
	BOOL bReturn;
	bReturn = GetSignerCertificateInfo(FilePath, &SignChain);
	
	CERT_NODE_INFO* tmpValue1 = NULL;
	SIGN_NODE_INFO* tmpValue = NULL;
	int signCheck = 0;
	while (SignChain != NULL) {
		GenericLL* tmp = SignChain;
		tmpValue = (SIGN_NODE_INFO*)tmp->data;
		/*if (tmpValue == NULL) { // once upon a time
			free(tmpValue);
			break;
		}*/
		SIGN_COUNTER_SIGN counterSignData;
		counterSignData = tmpValue->CounterSign;
		if (SignChain->next == NULL) {


			if (tmpValue->CounterSign.TimeStamp) {
				//printf("%ws \n", tmpValue->CounterSign.TimeStamp);
				if (data->timeStamp) {
					free(data->timeStamp);
					data->timeStamp = NULL;
				}
				strDataCopy(&data->timeStamp, tmpValue->CounterSign.TimeStamp);
			}


		}

		GenericLL* certtmp = tmpValue->CertChain;
		GenericLL* tmpCert = NULL;
		while (certtmp != NULL) {
			tmpCert = certtmp;
			tmpValue1 = (CERT_NODE_INFO*)certtmp->data;

			if (signCheck == 0) {
				if (data->publisher) {
					free(data->publisher);
					data->publisher = NULL;
				}
				strDataCopy(&data->publisher, tmpValue1->SubjectName);
				if (data->signAlg) {
					free(data->signAlg);
					data->signAlg = NULL;
				}
				strDataCopy(&data->signAlg, tmpValue1->SignAlgorithm);
				if (data->thumbprint) {
					free(data->thumbprint);
					data->thumbprint = NULL;
				}
				strDataCopy(&data->thumbprint, strupr(tmpValue1->Thumbprint));
				//printf("%s \n%s\n%s\n", data->publisher, data->signAlg, data->thumbprint);
				signCheck = 1;
			}

			/*if (certtmp->next == NULL) {
				strDataCopy(&data->publisher, tmpValue1->SubjectName);
				strDataCopy(&data->signAlg, tmpValue1->SignAlgorithm);
				strDataCopy(&data->thumbprint, tmpValue1->Thumbprint);
			}*/

			if (tmpValue1 != NULL) {
				if (tmpValue1->SubjectName) free(tmpValue1->SubjectName);
				if (tmpValue1->IssuerName) free(tmpValue1->IssuerName);
				if (tmpValue1->SignAlgorithm) free(tmpValue1->SignAlgorithm);
				if (tmpValue1->Thumbprint) free(tmpValue1->Thumbprint);
				if (tmpValue1->NotBefore) free(tmpValue1->NotBefore);
				if (tmpValue1->Version) free(tmpValue1->Version);
				if (tmpValue1->NotAfter) free(tmpValue1->NotAfter);
				if (tmpValue1->Serial) free(tmpValue1->Serial);
				free(tmpValue1);
			}
			certtmp = certtmp->next;
			if (tmpCert)
				free(tmpCert);
		}
		/*if (tmpValue)
			continue;*/
		if (tmpValue->CounterSign.TimeStamp)
			free(tmpValue->CounterSign.TimeStamp);
		if (tmpValue->DigestAlgorithm)
			free(tmpValue->DigestAlgorithm);
		if (tmpValue->Version)
			free(tmpValue->Version);

		SignChain = SignChain->next;

		if (tmp->data)
			free(tmp->data);
		if (tmp)
			free(tmp);
		//printf("\n\n");s
	}
}

__declspec(noinline) void errorCodeToStr(struct PEImgDetails* data) {
	switch (data->errorCode)
	{
	case FILE_SIZE_ZERO:
		strDataCopy(&data->errorCodeStr, "ZeroFileSize");
		break;
	case PEFILE_PARSE_BINARY_NULL:
		strDataCopy(&data->errorCodeStr, "InvalidFileStructure");
		break;
	case PEFILE_PARSE_BINARY_FAILED:
		strDataCopy(&data->errorCodeStr, "InvalidFileStructureParseFailed");
		break;
	case CHKADDR_FAILED:
		strDataCopy(&data->errorCodeStr, "InvalidOffsetToRead");
		break;
	case MZ_MAGIC_IN_CORRECT:
		strDataCopy(&data->errorCodeStr, "InCorrectMagicNumber");
		break;
	case UNKNOWN_PE_MAGIC:
		strDataCopy(&data->errorCodeStr, "InCorrectMismatchConfig");
		break;
	case IS_ZOHO_BINARY_NULL:
		strDataCopy(&data->errorCodeStr, "InvalidIsZohoBinary");
		break;
	case IS_ZOHO_BINARY_EXTRACT_RAW_SIGNED_DATA:
		strDataCopy(&data->errorCodeStr, "CertVerify_1_Failed_ExtractRawSigned");
		break;
	case IS_ZOHO_BINARY_PARSE_SIGNER_INFO:
		strDataCopy(&data->errorCodeStr, "CertVerify_2_Failed_ParseSignerInfo");
		break;
	case IS_ZOHO_BINARY_VERIFY_CERTFICATE_DATA:
		strDataCopy(&data->errorCodeStr, "CertVerify_3_Failed_VerifyCertData");
		break;
	case IS_ZOHO_BINARY_PARSE_CONTENT_INFO:
		strDataCopy(&data->errorCodeStr, "CertVerify_4_Failed_ParseContentInfo");
		break;
	case IS_ZOHO_BINARY_PEFILE_DIGEST_PE:
		strDataCopy(&data->errorCodeStr, "CertVerify_5_Failed_PeFileDigestCalculate");
		break;
	case IS_ZOHO_BINARY_PE_DIGEST_MISMATCH:
		strDataCopy(&data->errorCodeStr, "CertVerify_6_Failed_PeFileDigestCalculate");
		break;
	case IS_ZOHO_BINARY_VERIFY_SIGN_FAILED:
		strDataCopy(&data->errorCodeStr, "CertVerify_7_Failed_VerifySignFailed");
		break;
	default:
		break;
	}
}

_declspec(noinline) int pefile_parse_binary(FILE* fp, unsigned int pelen, struct pefile_context* ctx, struct PEImgDetails* data, Tree_t* TrustedCAtree)
{
	struct mz_hdr* mz = NULL;
	struct pe_hdr* pe = NULL;
	struct pe32_opt_hdr* pe32 = NULL;
	struct pe32plus_opt_hdr* pe64 = NULL;
	struct data_directory* ddir = NULL;
	struct data_dirent* dde;
	struct section_header* secs, * sec;
	size_t cursor, datalen = pelen;
	int ret = -1;



	if (chkaddr_func(0, 0, sizeof(*mz), datalen) == ELIBBAD) {
		goto cleanup;
	}
	mz = calloc(1, sizeof(struct mz_hdr));
	// if (1 != fpread(mz, sizeof(struct mz_hdr), 1, 0, fp)) 
	if(1 != freadW(mz, 0, sizeof(struct mz_hdr), 1, fp, data->fileSize))
	{ if (mz) { free(mz); }goto cleanup; }
	if (mz->magic != MZ_MAGIC) {
		data->errorCode = MZ_MAGIC_IN_CORRECT;
		ret = -ELIBBAD;
		goto cleanup;
	}

	cursor = sizeof(*mz);

	if (chkaddr_func(cursor, mz->peaddr, sizeof(*pe), datalen) == ELIBBAD) {
		goto cleanup;
	}
	pe = calloc(1, sizeof(struct pe_hdr));
	// if (1 != fpread(pe, sizeof(struct pe_hdr), 1, mz->peaddr, fp))
	if(1 != freadW(pe, mz->peaddr, sizeof(struct pe_hdr), 1, fp, data->fileSize))
	 { if (pe) free(pe);  goto cleanup; }

	data->characteristics = pe->flags;

	//printf("charact %X\n", data->characteristics);


	if (pe->magic != PE_MAGIC) {

		ret = -ELIBBAD;
		goto cleanup;
	}
	cursor = mz->peaddr + sizeof(*pe);

	if (chkaddr_func(0, cursor, sizeof(pe32->magic),datalen) == ELIBBAD) {
		goto cleanup;
	}
	pe32 = calloc(1, sizeof(struct pe32_opt_hdr));
	// if (1 != fpread(pe32, sizeof(struct pe32_opt_hdr), 1, cursor, fp)) 
	if(1 != freadW(pe32, cursor, sizeof(struct pe32_opt_hdr), 1, fp, data->fileSize))
	{
		if (pe32) 
			free(pe32); 
		pe32 = NULL;
		goto cleanup; 
	}


	pe64 = calloc(1, sizeof(struct pe32plus_opt_hdr));
	// if (1 != fpread(pe64, sizeof(struct pe32plus_opt_hdr), 1, cursor, fp)) 
	if(1 != freadW(pe64, cursor, sizeof(struct pe32plus_opt_hdr), 1, fp, data->fileSize))
	{ 
		if (pe64) 
			free(pe64); 
		pe64 = NULL;
		goto cleanup; 
	}

	size_t opt_hdr_start = cursor;

	switch (pe32->magic) {
	case PE_OPT_MAGIC_PE32:
		//DEBUG//printf("PE32 Maggic\n");
		if (chkaddr_func(0, cursor, sizeof(*pe32), datalen) == ELIBBAD) {
			goto cleanup;
		}
		ctx->image_checksum_offset = (unsigned int)((size_t)((char*)&pe32->csum - (char*)pe32) + cursor);
		ctx->header_size = pe32->header_size;
		cursor += sizeof(*pe32);
		ctx->n_data_dirents = pe32->data_dirs;
		//opt_hdr_start = pe32;
		break;

	case PE_OPT_MAGIC_PE32PLUS:
		//printf("\n\nPE32+ Maggic\n");
		if (chkaddr_func(0, cursor, sizeof(*pe64), datalen) == ELIBBAD) {
			goto cleanup;
		}
		ctx->image_checksum_offset = (unsigned int)((size_t)((char*)&pe64->csum - (char*)pe64) + cursor);
		ctx->header_size = pe64->header_size;
		cursor += sizeof(*pe64);
		ctx->n_data_dirents = pe64->data_dirs;
		//opt_hdr_start = pe64;
		break;

	default:
		//DEBUG//printf("Unknown PEOPT magic = %04hx\n", pe32->magic);
		data->errorCode = UNKNOWN_PE_MAGIC;
		ret = -ELIBBAD;
		goto cleanup;
	}

	//DEBUG//printf("checksum @ %x\n", ctx->image_checksum_offset);
	//DEBUG//printf("Optional Header Start : %d\nHeader size = %d %d\n", opt_hdr_start, ctx->header_size, opt_hdr_start + pe->opt_hdr_size);

	if (cursor >= ctx->header_size || ctx->header_size >= datalen) {
		data->errorCode = PEFILE_PARSE_BINARY_NULL;
		ret = -ELIBBAD;
		goto cleanup;
	}

	if (ctx->n_data_dirents > (ctx->header_size - cursor) / sizeof(*dde))
	{
		data->errorCode = PEFILE_PARSE_BINARY_NULL;
		ret = -ELIBBAD;
		goto cleanup;
	}

	ddir = calloc(1, sizeof(struct data_directory));
	// if (0 == fpread(ddir, sizeof(struct data_directory), 1, cursor, fp)) 
	if(1 != freadW(ddir, cursor, sizeof(struct data_directory), 1, fp, data->fileSize))
	{ 
		if (ddir) {
			free(ddir); 
		}
		ddir = NULL;
		goto cleanup; 
	}

	if (ddir) {
		ctx->cert_dirent_offset = (unsigned int)((uintptr_t)&ddir->certs - (uintptr_t)ddir + cursor);
		ctx->certs_size = ddir->certs.size;
	}

	cursor += sizeof(*dde) * ctx->n_data_dirents;

	if (ddir)
		ctx->resource_viirtualaddr = ddir->resources.virtual_address;
	//DEBUG//printf("cert = %x @%x \n", ctx->sig_len, ctx->sig_offset);

	ctx->n_sections = pe->sections;
	if (ctx->n_sections > (ctx->header_size - cursor) / sizeof(*sec)) {
		data->errorCode = PEFILE_PARSE_BINARY_NULL;
		ret = -ELIBBAD;
		goto cleanup;
	}
	secs =(struct section_header*) ctx->secs = (struct section_header*)calloc(ctx->n_sections, sizeof(struct section_header));
	// if (1 != fpread(ctx->secs, sizeof(struct section_header) * ctx->n_sections, 1, cursor, fp)) 
	if(1 != freadW((void*)ctx->secs, cursor, sizeof(struct section_header) * ctx->n_sections, 1, fp, data->fileSize))
	{ if (ctx->secs) { free((void*)ctx->secs); }goto cleanup; }
	//DEBUG//printf("Section starts at %d\n", cursor + (sizeof(struct section_header) * ctx->n_sections));

	/*for (int i = 0; i < ctx->n_sections; i++) {
		printf("%s \n", (ctx->secs +i)->name);
	}*/

	// Get Embeded Data 
	if (ddir == NULL) {
		data->errorCode = PEFILE_PARSE_BINARY_NULL;
		goto cleanup;
	}
	if (ddir->certs.virtual_address && ddir->certs.size) {
		// EMBEDED SIGNATURE GETTING 
		if (chkaddr_func(ctx->header_size, ddir->certs.virtual_address,
			ddir->certs.size, datalen) == ELIBBAD) {
			goto cleanup;
		}
		ctx->sig_offset = ddir->certs.virtual_address;
		ctx->sig_len = ddir->certs.size;

		//rewind(fp); // FILE* 

		ret = pefile_strip_sig_wrapper(fp, ctx, data);

		if (ctx->pkcs == NULL) {
			data->errorCode = PEFILE_PARSE_BINARY_NULL;
			goto cleanup;
		}
		/* 1. checking the verification status of a binary file using two different methods. It first attempts to verify using isZohoBinary, and if that fails, it falls back to using VerifyEmbeddedSignature. After verification, it also fetches signer details if the signature is valid.
		* method 1: isZohoBinary is faster and consume less CPU. 
		*			we notes some certificate can't verify need some n/w support. this type of situation use method 2.
		* method 2: VerifyEmbeddedSignature is slwoer and consume higher CPU. 
		*/
		isZohoBinary(fp, ctx->pkcs, pelen, ctx, data, TrustedCAtree, data);
		if (data->verified == 0) {
			size_t len = strlen(data->filePath) + 1;
			wchar_t* wtext = (wchar_t*)malloc(len * sizeof(wchar_t));
			if (wtext == NULL) {
				fprintf(stderr, "Memory allocation failed\n");
				return 1;
			}
			mbstowcs(wtext, data->filePath, len);//Plus null
			LPCWSTR FilePath = wtext;
			VerifyEmbeddedSignature(FilePath, data);
			if (data->verified == 1) {
				fetchSignerDetailsFromFile(FilePath,data);
				errorCodeToStr(data);
				// error code 
			}
			if (wtext != NULL) {
				free(wtext);
			}
		}

		if (data->verified == 1) {
			//printf("SignType:	Embeded\n");
			char* signType = "Embeded";
			strDataCopy(&data->signType, signType);
			/*int count = 0;
			char buffer1[200] = { 0 };
			for (DWORD i = 0; i < strlen(data->thumbprint); i++)
			{
				count = strlen(buffer1);
				sprintf((char*)&buffer1[count], "%02X", (UINT8)(data->thumbprint)[i]);
			}
			printf("ThumbPrint:	 %s\n", buffer1);
			printf("Status:		embeded verified\n");*/
		}
	}
	else {

		WCHAR* CataFile = NULL;


		BOOL bReturn;
		PVOID   Context = NULL;
		do
		{
			if (CataFile)
				break;
			bReturn = CryptCATAdminAcquireContext(&Context, NULL, 0);
			if (!bReturn)
			{
				////printf("CryptCATAdminAcquireContext fail \n");
				//data->errorCode = PEFILE_PARSE_BINARY_NULL;

				//goto cleanupCatlog;
				break;
			}
			char* digest = NULL;
			int digestLen = 0x00;
			/*
				HANDLE FileHandle = CreateFile(data->filePathW, GENERIC_READ,
					7,
					NULL,
					OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS,
					NULL
				);
				if (INVALID_HANDLE_VALUE == FileHandle)
				{
					printf("CreateFileW fail \n");
					break;
				}
				 Calculate file hash.
				DWORD dwHashSize = 0x00;
				PBYTE szBuffer = NULL;
				bReturn = MyCryptCalcFileHash(FileHandle, &digest, &digestLen);
				if (!bReturn) {
					break;
				}
				CloseHandle(FileHandle);
			*/
			ret = pefile_digest_pe(fp, pelen, ctx, MBEDTLS_MD_SHA1, &digest, &digestLen, data);


			if (ret < 0) {
				break;
			}
			// Get catalog Context structure.
			UINT     uiCataLimit = 0x00;
			HCATINFO CataContext = NULL;
			do
			{
				// Probe catalog Context structure layer.
				CataContext = CryptCATAdminEnumCatalogFromHash(Context,
					digest,
					digestLen,
					0,
					uiCataLimit == 0 ? NULL : &CataContext
				);
				uiCataLimit++;
			} while (CataContext);
			uiCataLimit--;

			for (UINT uiIter = 0; uiIter < uiCataLimit; uiIter++)
			{
				// Get specified catalog Context structure.
				CataContext = CryptCATAdminEnumCatalogFromHash(Context,
					digest,
					digestLen,
					0,
					&CataContext
				);
			}
			if (digest != NULL) {
				free(digest);
				digest = NULL;
			}
			if (!CataContext)
			{
				if (Context)
				{
					bReturn = CryptCATAdminReleaseContext(Context, 0);
					Context = NULL;

				}
				////printf("Unverified\n");
				data->errorCode = PEFILE_PARSE_BINARY_NULL;
				//goto cleanupCatlog;
				break;
			}


			// Get catalog information.
			CATALOG_INFO CataInfo = { 0 };
			CataInfo.cbStruct = sizeof(CATALOG_INFO);
			bReturn = CryptCATCatalogInfoFromContext(CataContext, &CataInfo, 0);
			if (bReturn)
			{
				/*CataFile = malloc(sizeof(wchar_t));*/
				CataFile = CataInfo.wszCatalogFile;
				size_t len = wcstombs(NULL, CataFile, 0) + 1;
				char* CataFileStr = (char*)calloc(len,sizeof(char));
				wcstombs(CataFileStr, CataFile, len);
				
				strDataCopy(&data->cataFile, CataFileStr);
				if (CataFileStr) {
					free(CataFileStr);
				}
				//printf("CataFIle %s \n", data->cataFile);
			}

			// Release catalog Context structure.
			if (CataContext) {
				bReturn = CryptCATAdminReleaseCatalogContext(Context, CataContext, 0);
				CataContext = NULL;
			}
			// Release signature Context structure.
			if (Context)
			{
				bReturn = CryptCATAdminReleaseContext(Context, 0);
				Context = NULL;
			}
		} while (FALSE);

		char* SignType = " ";

		GenericLL* SignChain = NULL;

		if ((is_wstring_not_empty((wchar_t*)CataFile) == 1))
		{

			/* 1. checking the verification status of a binary file using two different methods. It first attempts to verify using verifyCatlogFileAndGetData, and if that fails, it falls back to using VerifyEmbeddedSignature. After verification, it also fetches signer details if the signature is valid.
			* method 1: verifyCatlogFileAndGetData is faster and consume less CPU.
			*			we notes some certificate can't verify need some n/w support. this type of situation use method 2.
			* method 2: VerifyEmbeddedSignature is slower and consume higher CPU.
			*/
			verifyCatlogFileAndGetData(CataFile, data, NULL);
			
			//printf("verified %d\n", data->verified);
			if (data->verified == 0) {
				VerifyEmbeddedSignature(CataFile, data);
				if (data->verified == 1) {
					fetchSignerDetailsFromFile(CataFile, data);
					errorCodeToStr(data);
				}
			}

			if (data->verified == 1) {
				SignType = "CATALOG";
				strDataCopy(&data->signType, SignType);
			}
		}
		
	}




cleanup:
	if (mz) free(mz);
	if (pe) free(pe);
	if (pe32) free(pe32);
	if (pe64) free(pe64);
	if (ddir) free(ddir);
	return 0;
}


// This Api is help to extract File Signing details and Resource of the PE files.
__declspec(noinline) int __cdecl verifier(BYTE* cbbyte, size_t size, struct _iobuf* fp, struct PEImgDetails* data, Tree_t* TrustedCAtree) {
	//FILE* fp;	
	size_t lSize;
	struct pefile_context ctx = { 0 };
	//initFileInfoDetails(fdata);

	if (!fp) exit(1);
	lSize = size;
	//rewind(fp);
	memset(&ctx, 0, sizeof(struct pefile_context));
	int ret;
	char* OriginalFileName = NULL;
	unsigned int pelen = 0;

	ret = pefile_parse_binary(fp, (unsigned int)lSize, &ctx, data, TrustedCAtree);


	if (ret < 0) {
		//data->errorCode = PEFILE_PARSE_BINARY_FAILED;
		return ret;
	}
	parse_originalfilename_File(fp, (unsigned int)lSize, &ctx, &OriginalFileName, data);

	if (ctx.pkcs) {
		free(ctx.pkcs);
	}
	if (ctx.secs) free((void*)ctx.secs);
	return 0;
}

