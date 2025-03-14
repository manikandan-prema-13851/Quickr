#ifndef FHEADER_H
#define FHEADER_H

#pragma warning(error : 4101) // Treat C4101 as an error
#include<stdio.h>
#include<Windows.h>
#include<Wincrypt.h>
#pragma comment(lib,"Shlwapi.lib")
#include"Shlwapi.h"
#include <time.h>
#include <stdint.h>

// Engine Working Mode

#define MC_MALWARE 1
#define MC_BENIGN 0
#define MC_UNKNOWN 2


#define NOVALUE "n/a"
#define NOVALUELEN 4
enum enumflags
{
	ENUM_FILE = 1,
	ENUM_DIR,
	ENUM_BOTH
};

#define owner_read  0400 // S_IRUSR
#define owner_write  0200 // S_IWUSR
#define owner_exec  0100 // S_IXUSR
#define owner_all  0700 // S_IRWXU
#define group_read  040 // S_IRGRP
#define group_write  020 // S_IWGRP
#define group_exec  010 // S_IXGRP
#define group_all  070 // S_IRWXG
#define others_read  04 // S_IROTH
#define others_write  02 // S_IWOTH
#define others_exec  01 // S_IXOTH
#define others_all  07 // S_IRWXO
#define BUFSIZE 16384
#define MD5LE  16
#define SHA1  20
#define SHA256 32
#define SHA512 64
#define SHA1LEN  20

enum FileParseStatus {
	FILE_SIZE_ZERO =  10010000,
	PEFILE_PARSE_BINARY_NULL =  10010001,
	PEFILE_PARSE_BINARY_FAILED =  10010010,
	CHKADDR_FAILED =  10010011,
	MZ_MAGIC_IN_CORRECT =  10010100,
	UNKNOWN_PE_MAGIC =  10010101,
	IS_ZOHO_BINARY_NULL =  10010110 ,// NULL,
	IS_ZOHO_BINARY_FAILED =  10010111 ,// FAILED,
	IS_ZOHO_BINARY_EXTRACT_RAW_SIGNED_DATA =  10011000 ,// extractRawSignedData ,
	IS_ZOHO_BINARY_PARSE_SIGNER_INFO =  10011001   ,// parseSignerInfo ,
	IS_ZOHO_BINARY_VERIFY_CERTFICATE_DATA =  10011010 ,// verifyCertficateData,
	IS_ZOHO_BINARY_PARSE_CONTENT_INFO =  10011011 ,// parseContentInfo,
	IS_ZOHO_BINARY_PEFILE_DIGEST_PE =  10011100 ,// pefile_digest_pe,
	IS_ZOHO_BINARY_PE_DIGEST_MISMATCH =  10011101 ,
	IS_ZOHO_BINARY_VERIFY_SIGN_FAILED =  10011110 ,// VerifySignature ,
};

struct McAnalysis {
	float featureprob;
	float importprob;
	float combineprob;
	int isMcMalware;

	char* patternString;
	size_t patternOffset;
	int isYaraMalware;
};;

struct PEImgDetails {
	long int fileSize;
	char* filePath;
	char* publisher;
	char* timeStamp;
	char* vSignChainVersion;
	char* digestAlgorithm;
	char* imphaseHash;
	char* imphashString;
	char* permission;
	char* company;
	char* product;
	char* internalName;
	char* copyRights;
	char* orgFileName;
	char* productVersion;
	char* fileVersion;
	char* fileDescription;
	char* mimeType;
	char* fileTypeExt;
	char* writeTime;
	char* accessTime;
	char* createTime;
	char* MD5value;
	char* SHA1value;
	char* SHA256value;
	char* SHA512value;
	char* status;
	char* thumbprint;
	char* signAlg;
	char* signType;
	char* parserVersionCode;
	BOOL verified;
	char* cataFile;
	DWORD characteristics;
	float fullFeatureArr[2224];
	float impFeatureArr[997];
	int isMalware;
	int errorCode;
	char* importFunctionString;
	wchar_t* filePathW;
	char* errorCodeStr;
	struct McAnalysis mcAnalysis;
};

__declspec(noinline) void printImgDetails(struct PEImgDetails*, int printDetails);
__declspec(noinline) void initImgDetails(struct PEImgDetails*);
__declspec(noinline) void filePermission(struct PEImgDetails* data);
__declspec(noinline) int freadW(void* data, size_t offset, size_t elementSize, size_t  elementCount, LPVOID mappedView, size_t fileSize);
#endif // !HEADER_H
