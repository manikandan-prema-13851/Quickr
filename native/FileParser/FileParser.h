#ifndef FILEPARSER_H
#define FILEPARSER_H

#include "pe_hash.h"
#include "hash.h"
#include "signature.h"
#include "asn1.h"
#include "oid.h"
#include <time.h>
#include <crtdbg.h>
#include "Header.h"	
#include"fileExt.h" 	
#include <sys/stat.h>	
#include <sys/types.h>
#include "GenericLL.h"
#include "fileSigningDetails.h"

#include "PatternScanner/PatternScanner.h"
#pragma warning(error : 4013)

typedef int (*Compare)(const char*, const char*);


#define READ_BYTE(p) (((unsigned char*)(p))[0])
#define READ_WORD(p)  ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8))
#define READ_DWORD(p) ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8) |  ((((unsigned char*)(p))[2]) << 16) | ((((unsigned char*)(p))[3]) << 24))
#define PAD(x) (((x) + 3) & 0xFFFFFFFC)			//offset have to be a multiple of 4.

#define RETURN_ON_ERROR(ret) if (ret < 0) {          \
/*printf("Returning now......%d\n", ret);*/ \
return ret; \
}  
struct Node_t {
	struct Node_t* left;
	struct Node_t* right;
	char* key;
	struct Certificate* value;
};


struct Tree {
	struct Node_t* root;
};


typedef struct HashBind {
	char* cKeyIdentifier;
	void* vValue;
} HashBind;




struct ExtractedSignedData {

	int Version;

	char* DigestAlgorithmIdentifiers;
	int lenDigestAlgorithmIdentifiers;

	char* ContentInfo;
	int lenContentInfo;

	char* Certificates;
	int lenCertificates;

	char* SignerInfos;
	int lenSignerInfos;

};

struct ParsedContentInfo {
	char* PEHashStr;
	int lenPEHashStr;
	mbedtls_md_type_t PEHashAlgo;
	void* SPCIndirectDataContext;
	char* ContentInfoHashStr;
	int lenContentInfoHashStr;
};

struct ParsedCertInfo {
	char* SignerPublicKey;
	int lenSignerPublicKey;
	int SignerExponent;
	char* SignerCertThumbprint;
	struct Certificate* SigerCert;
	int CertChainVerified;
};

struct ParsedSignerInfo {
	int version;
	char* SignedCertificateSerialNumber;
	int lenSignedCertificateSerialNumber;
	mbedtls_md_type_t ContentInfoHashAlgo;
	char* ContentInfoHashStrFromAuthAtr;
	int lenContentInfoHashStrFromAuthAtr;
	char* AuthAtrHashStr;
	int lenAuthAtrHashStr;
	char* EncryptedDigest;
	int lenEncryptedDigest;
};


struct ParsedSignedData {
	int version;
	mbedtls_md_type_t SignedDataHashAlgo;
	struct ParsedContentInfo ParsedContentInfo;
	struct ParsedCertInfo ParsedCertInfo;
	struct ParsedSignerInfo ParsedSignerInfo;
	struct PESignInfo PESignInfo;
	/*
	*	MSCode PE Hash data
	*/
	char* digest;
	int digestLen;
};

struct regData {
	int size;
	char data[10000];
};



typedef struct Tree Tree_t;

typedef struct {
	Tree_t* TrustedCAtree;
	struct ExtNode* root;
	struct hashTableMalwareFullFunc* mapMalwareFullFunc;
} FileParserTreeData;

typedef struct {
	int mcScanFlag;
	int yaraScanFlag;
	int printPEData;
} ScannerConfig;

__declspec(noinline) int CmpStr(const char* a, const char* b);
__declspec(noinline) Tree_t* createTree();
__declspec(noinline) int prepareAuthCertsFromRegistry(Tree_t* TrustedCAtree);
__declspec(noinline) void avlPrint(Tree_t*, char*);
__declspec(noinline) struct Node_t* searchNode_t(char*, struct Node_t*, Compare);
__declspec(noinline) struct Node_t* createNode_t();
__declspec(noinline) void printCertificate(struct Certificate*);
__declspec(noinline) struct PEImgDetails* startPE(wchar_t* str, ScannerConfig* malDetEngine, LPVOID fp);
__declspec(noinline) struct PEImgDetails* PEFileScanner(wchar_t* baseDir, ScannerConfig* malDetEngine);
__declspec(noinline) void printImgDetails(struct PEImgDetails*, int printDetails);
__declspec(noinline) void freeImgDetails(struct PEImgDetails* data);
__declspec(noinline) void GetFileDetail(wchar_t* filepath, struct ExtNode* root, struct PEImgDetails* data, Tree_t* TrustedCAtree, FILE* fp);
__declspec(noinline) int initPEParser(wchar_t*);

__declspec(noinline) void freeExtNode1(struct ExtNode* extNode);

__declspec(noinline) int getAllFilesFileParser(const char* rootDir, BOOL subDirectories, ScannerConfig* malDetEngine, int printDetails);
__declspec(noinline) int getAllFilesFileParserW(WCHAR* rootDir, BOOL subDirectories, ScannerConfig* malDetEngine, int printDetails);
__declspec(noinline) int FPSha256Calculation(const wchar_t* filepath,  char* HashValue);
int FPSha256CalculationWithHandle(BCRYPT_ALG_HANDLE algHandle1, const wchar_t* filepath, char* HashValue);
// INTERNAL API
__declspec(noinline) int __cdecl verifier(BYTE* cbbyte, size_t size, struct _iobuf* fp, struct PEImgDetails* data, Tree_t* TrustedCAtree);
__declspec(noinline) int  ParseCertificate(char* buffer, char* end, size_t lSize, struct Certificate* cert);

// UTIL.h
__declspec(noinline) void strDataCopy(char** destination, char* source);
__declspec(noinline) void persistCharArray(char** key, size_t len);
__declspec(noinline) void strDataNCopy(char** destination, char* source, size_t strLenSource);
__declspec(noinline)  int freadW(void* data, size_t offset, size_t elementSize, size_t  elementCount, LPVOID mappedView, size_t fileSize);
__declspec(noinline) int enterTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef);
__declspec(noinline) int skipTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef);
__declspec(noinline) void printAsHex(char* cp, size_t len);
__declspec(noinline) void printAsText(char* cp, size_t len);


// utils.c
__declspec(noinline) int freePEParserStruct(Tree_t** TrustedCAtree, struct ExtNode** root, struct hashTableMalwareFullFunc* mapMalwareFullFunc);


__declspec(noinline) void verifyCatlogFileAndGetData(const wchar_t* filename, struct PEImgDetails* data, Tree_t* TrustedCAtree);
#endif