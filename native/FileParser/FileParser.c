#include < wchar.h >
#include<string.h>
#include"FileParser.h"
#include "fUtil.h"
#include "FeatureExtractor/FeatureHeader.h"
#include "embeded.h"
#include "MCHeader.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

#pragma warning(disable : 26451)
#pragma warning (disable: 4996)	
#pragma warning(disable:6031)
#pragma warning(disable:4146)


#define MAX_LIMIT 256
#define DEBUG_NEW new(__FILE__, __LINE__)
#define new DEBUG_NEW

#define IMAGE_DOS_SIGNATURE 0x5A4D  // 'MZ'


FileParserTreeData fileParserTreeData = {0}; 
int corruptedField = 0;

typedef struct CERT_NODE {
	char* SubjectName;
	char* IssuerName;
	char* Version;
	char* Serial;
	char* Thumbprint;
	char* NotBefore;
	char* NotAfter;
	char* SignAlgorithm;
	WCHAR* CRLpoint;
} CERT_NODE;
CERT_NODE stCertNode[100];
int fileCount = 0;


#ifdef   _DEBUG	
#define  SET_CRT_DEBUG_FIELD(a) \	_CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \	_CrtSetDbgFlag(~(a)&_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#else	
#define  SET_CRT_DEBUG_FIELD(a)   ((void) 0)	
#define  CLEAR_CRT_DEBUG_FIELD(a) ((void) 0)	
#endif


__declspec(noinline) void persistCharArray(char** key, size_t len) {

	size_t lendup = len + 1;
	char* name = (char*)calloc((lendup), sizeof(char));
	if (name) {
		//ZeroMemory(name, lendup);
		memcpy(name, *key, len);
		*key = name;
	}
}


__declspec(noinline) BOOL CalculateCertCRLpoint(DWORD cExtensions, CERT_EXTENSION rgExtensions[], WCHAR** CRLpoint) {
	BOOL                    bReturn = FALSE;
	BYTE                    btData[512] = { 0 };
	wchar_t                 csProperty[512] = { 0 };
	ULONG                   ulDataLen = 512;
	PCRL_DIST_POINTS_INFO   pCRLDistPoint = (PCRL_DIST_POINTS_INFO)btData;
	PCRL_DIST_POINT_NAME    dpn = NULL;
	PCERT_EXTENSION         pe = NULL;

	/*CRLpoint.clear();*/
	*CRLpoint = L" ";
	pe = CertFindExtension(szOID_CRL_DIST_POINTS, cExtensions, rgExtensions);
	if (!pe)
	{
		return FALSE;
	}
	bReturn = CryptDecodeObject(MY_ENCODING, szOID_CRL_DIST_POINTS,
		pe->Value.pbData,
		pe->Value.cbData,
		CRYPT_DECODE_NOCOPY_FLAG,
		pCRLDistPoint, &ulDataLen
	);
	if (!bReturn)
	{
		return FALSE;
	}
	for (ULONG idx = 0; idx < pCRLDistPoint->cDistPoint; idx++)
	{
		dpn = &pCRLDistPoint->rgDistPoint[idx].DistPointName;
		for (ULONG ulAltEntry = 0; ulAltEntry < dpn->FullName.cAltEntry; ulAltEntry++)
		{
			if (wcslen(csProperty) > 0)
			{
				wcscat_s(csProperty, 512, L";");
			}
			wcscat_s(csProperty, 512, dpn->FullName.rgAltEntry[ulAltEntry].pwszURL);
		}
	}
	WCHAR* CRLpointDUP = csProperty;

	*CRLpoint = (WCHAR*)calloc(wcslen(CRLpointDUP), sizeof(WCHAR));
	if (*CRLpoint) {
		//wmemset(*CRLpoint, 0, wcslen(CRLpointDUP));
		wcsncpy(*CRLpoint, CRLpointDUP, wcslen(CRLpointDUP));
	}
	return TRUE;
}

__declspec(noinline)  int freadW(void* data, size_t offset, size_t elementSize, size_t  elementCount, LPVOID mappedView, size_t fileSize) {
	// fread Wrapper
	if (!data || elementSize > fileSize || offset > fileSize || (elementSize + offset) > fileSize) {
		corruptedField = 1;
		return 0;
	}
	//fread(data, elementSize, elementCount, fp);
	//data = (void*)(&fp + offset);
	void* mappedData = (void*)((BYTE*)mappedView + offset);
	memcpy(data, mappedData, elementCount * elementSize);
	return 1;
}

void filePermission(struct PEImgDetails* data) {
	char permissionVariable[10] = "---------";

	if (wcslen(data->filePathW) == 0) {
		strDataCopy(&data->permission, permissionVariable);
		return;
	}

	struct _stat fileStat;
	if (_wstat(data->filePathW, &fileStat) != 0) {
		strDataCopy(&data->permission, permissionVariable);
		return;
	}

	data->fileSize = fileStat.st_size;
	permissionVariable[0] = (fileStat.st_mode & owner_read) ? 'r' : '-'; //owner_read	
	permissionVariable[1] = (fileStat.st_mode & owner_write) ? 'w' : '-'; //owner_write	
	permissionVariable[2] = (fileStat.st_mode & owner_exec) ? 'x' : '-'; //owner_exec	
	permissionVariable[3] = (fileStat.st_mode & group_read) ? 'r' : '-'; //group_read	
	permissionVariable[4] = (fileStat.st_mode & group_write) ? 'w' : '-'; //group_write	
	permissionVariable[5] = (fileStat.st_mode & group_exec) ? 'x' : '-'; //group_exec	
	permissionVariable[6] = (fileStat.st_mode & others_read) ? 'r' : '-'; //others_read	
	permissionVariable[7] = (fileStat.st_mode & others_write) ? 'w' : '-'; //others_write	
	permissionVariable[8] = (fileStat.st_mode & others_exec) ? 'x' : '-'; //others_exec	
	permissionVariable[9] = '\0';

	strDataCopy(&data->permission, permissionVariable);

	char t[100] = "";

	strftime(t, sizeof(t), "%d/%m/%Y %H:%M:%S", localtime(&fileStat.st_mtime));
	strDataCopy(&data->writeTime, t);

	strftime(t, sizeof(t), "%d/%m/%Y %H:%M:%S", localtime(&fileStat.st_atime));
	strDataCopy(&data->accessTime, t);

	strftime(t, sizeof(t), "%d/%m/%Y %H:%M:%S", localtime(&fileStat.st_ctime));
	strDataCopy(&data->createTime, t);
}

__declspec(noinline) void hashDetail(struct PEImgDetails* data, struct ExtNode* root, Tree_t* TrustedCAtree, FILE* fileptr) {
	BCRYPT_ALG_HANDLE algHandle = NULL;
	BCRYPT_HASH_HANDLE hashHandle = NULL;
	BYTE* hashObject = NULL;
	BYTE hashBuffer[32];

	DWORD hashObjectLength = 0, resultLength = 0;


	size_t bufsize1 = BUFSIZE;
	size_t sizeoffile = data->fileSize;
	size_t tempsizeoffile = sizeoffile;

	if (sizeoffile < BUFSIZE) {
		bufsize1 = sizeoffile;
	}

	BYTE* cbbyte = (BYTE*)calloc(bufsize1, sizeof(BYTE));
	if (!cbbyte) {
		wprintf(L"Memory allocation failed for buffer.\n");
		return;
	}

	if (1 != freadW(cbbyte, 0, bufsize1, 1, fileptr, data->fileSize)) {
		free(cbbyte);
		return;
	}

	verifier(cbbyte, sizeoffile, fileptr, data, TrustedCAtree);

	struct MimeValue* ext = searchTrie(root, cbbyte, bufsize1);
	if (ext == NULL) {
		wchar_t* extValue = wcsrchr(data->filePathW, L'.');
		if (extValue != NULL) {
			wstrDataToStrCopy(&data->fileTypeExt, extValue);
			_strupr_s(data->fileTypeExt, strlen(data->fileTypeExt) + 1);
			
		}
		else {
			strDataNCopy(&data->fileTypeExt, NOVALUE, NOVALUELEN);
		}
		strDataNCopy(&data->mimeType, NOVALUE, NOVALUELEN);
	}
	else {
		if (strcmp(ext->exttype, "EXE") == 0) {
			if (((data->characteristics) & (0x1 << 13)) == 8192) {
				strDataCopy(&data->fileTypeExt, "DLL");
			}
			else {
				strDataCopy(&data->fileTypeExt, ext->exttype);
			}
		}
		else {
			strDataCopy(&data->fileTypeExt, ext->exttype);
		}
		strDataCopy(&data->mimeType, ext->mimetype);
	}

	NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptOpenAlgorithmProvider failed: 0x%x\n", ntStatus);
		return;
	}

	// Get the length of the hash object
	ntStatus = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectLength, sizeof(DWORD), &resultLength, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptGetProperty (BCRYPT_OBJECT_LENGTH) failed: 0x%x\n", ntStatus);
		return;
	}
	hashObject = (BYTE*)malloc(hashObjectLength);
	if (!hashObject) {
		wprintf(L"Memory allocation failed for hash object.\n");
		return;
	}
	ntStatus = BCryptCreateHash(algHandle, &hashHandle, hashObject, hashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptHashData failed: ");
		BCryptDestroyHash(hashHandle);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		free(cbbyte);
		return;
	}
	else {
		size_t offsize = 0;
		float sum = 0;
		float Histogramvalue[256] = { 0 };
		float byteArray[256] = { 0 };

		while (sizeoffile > 0) {
			if (sizeoffile > BUFSIZE) {
				freadW(cbbyte, offsize, BUFSIZE, 1, fileptr, data->fileSize);
			}
			else {
				freadW(cbbyte, offsize, sizeoffile, 1, fileptr, data->fileSize);
				bufsize1 = sizeoffile;
			}

			ntStatus = BCryptHashData(hashHandle, cbbyte, (ULONG)bufsize1, 0);
			if (!NT_SUCCESS(ntStatus)) {
				wprintf(L"BCryptHashData failed: 0x%x\n", ntStatus);
				return;
			}

			for (int i = 0; i < bufsize1; i++) {
				int val = cbbyte[i] & 0xFF;
				Histogramvalue[val]++;
			}


			sizeoffile -= bufsize1;
			offsize += bufsize1;
		}

		for (int HistogramvalueLoop = 0; HistogramvalueLoop < 256; HistogramvalueLoop++) {
			byteArray[HistogramvalueLoop] = Histogramvalue[HistogramvalueLoop];
			sum = sum + Histogramvalue[HistogramvalueLoop];
		}

		for (int i = 0; i < 256; i++) {
			data->fullFeatureArr[i] = (byteArray[i] / sum);
		}
		
	}

	ntStatus = BCryptFinishHash(hashHandle, hashBuffer, 32, 0);
	if (NT_SUCCESS(ntStatus)) {
		int count = 0;
		char buffer[200] = { 0 };
		for (DWORD i = 0; i < SHA256; i++)
		{
			count = (int)strlen(buffer);
			sprintf(&buffer[count], "%02X", hashBuffer[i]);
		}
		if (data != NULL)
		{
			_strupr(buffer);
			strDataNCopy(&data->SHA256value, buffer, 65);

		}
	}
	if (hashHandle) BCryptDestroyHash(hashHandle);
	if (algHandle) BCryptCloseAlgorithmProvider(algHandle, 0);

	if (hashObject) {
		free(hashObject);
	}


	free(cbbyte);
}


__declspec(noinline) void printImgDetails(struct PEImgDetails* data, int printDetails) {
	if (printDetails != 1)
		return;

	FILE* fptr = fopen("full_feature_array.csv", "a");

	fprintf(fptr, "%s,", data->filePath);
	for (int i = 0; i < 2224; i++)
		fprintf(fptr, "%f,", data->fullFeatureArr[i]);

	fprintf(fptr, "\n");
	if (fptr) {
		fclose(fptr);
		fptr = NULL;
	}
	fptr = fopen("imp_feature_array.csv", "a");

	fprintf(fptr, "%s,", data->filePath);
	for (int i = 0; i < 997; i++)
		fprintf(fptr, "%f,", data->impFeatureArr[i]);
	fprintf(fptr, "\n");

	if (fptr) {
		fclose(fptr);
		fptr = NULL;
	}


	if (data)
	{

		fptr = fopen("unified_feautre_array.csv", "a");
		fprintf(fptr, "%s,", data->filePath);

		for (int i = 0; i < 838; ++i) {   // 0 - 838
			fprintf(fptr, "%f,", data->fullFeatureArr[i]);
		}
		for (int i = 1862; i < 2224; ++i) { // 837 + 362 = 1199
			fprintf(fptr, "%f,", data->fullFeatureArr[i]);
		}
		for (int i = 0; i < 997; i++) { // 1199 + 2093 = 3292
			fprintf(fptr, "%f,", data->impFeatureArr[i]);
		}

		fprintf(fptr, "\n");

		if (fptr) {
			fclose(fptr);
			fptr = NULL;
		}

		fptr = fopen("file_scan_summary.csv", "a");
		fprintf(fptr, "%s,", data->SHA256value);
		fprintf(fptr, "%d,", data->verified);
		fprintf(fptr, "%f,", data->mcAnalysis.featureprob);
		fprintf(fptr, "%f,", data->mcAnalysis.importprob);
		fprintf(fptr, "%f,", data->mcAnalysis.combineprob);
		fprintf(fptr, "%d,", data->mcAnalysis.isMcMalware);
		fprintf(fptr, "%s,", data->mcAnalysis.patternString);
		fprintf(fptr, "%zu,", data->mcAnalysis.patternOffset);
		fprintf(fptr, "%d,", data->mcAnalysis.isYaraMalware);
		fprintf(fptr, "%d,", data->isMalware);
		fprintf(fptr, "%s,", data->errorCodeStr);
		fprintf(fptr, "%d,", data->errorCode);
		fprintf(fptr, "%s\n", data->filePath);

		if (fptr) {
			fclose(fptr);
			fptr = NULL;
		}
		fptr = _wfopen(L"output.txt", L"a");
		fwprintf(fptr, L"filePath:\t %S\n", data->filePath);
		fwprintf(fptr, L"filePathW:\t%s\n", data->filePathW);
		fwprintf(fptr, L"fileSize:\t %ld\n", data->fileSize);
		fwprintf(fptr, L"publisher:\t %S\n", data->publisher);
		fwprintf(fptr, L"timeStamp:\t %S\n", data->timeStamp);
		fwprintf(fptr, L"permission:\t %S\n", data->permission);
		fwprintf(fptr, L"company:\t %S\n", data->company);
		fwprintf(fptr, L"product:\t %S\n", data->product);
		fwprintf(fptr, L"internalName:\t %S\n", data->internalName);
		fwprintf(fptr, L"fileDescription:\t %S\n", data->fileDescription);
		fwprintf(fptr, L"copyRights:\t %S\n", data->copyRights);
		fwprintf(fptr, L"orgFileName:\t %S\n", data->orgFileName);
		fwprintf(fptr, L"productVersion:\t %S\n", data->productVersion);
		fwprintf(fptr, L"fileVersion:\t %S\n", data->fileVersion);
		fwprintf(fptr, L"mimeType:\t %S\n", data->mimeType);
		fwprintf(fptr, L"fileTypeExt:\t %S\n", data->fileTypeExt);
		fwprintf(fptr, L"writeTime:\t %S\n", data->writeTime);
		fwprintf(fptr, L"accessTime:\t %S\n", data->accessTime);
		fwprintf(fptr, L"createTime:\t %S\n", data->createTime);
		fwprintf(fptr, L"MD5:\t %S\n", data->MD5value);
		fwprintf(fptr, L"SHA1:\t %S\n", data->SHA1value);
		fwprintf(fptr, L"SHA256:\t %S\n", data->SHA256value);
		fwprintf(fptr, L"SHA512:\t %S\n", data->SHA512value);
		fwprintf(fptr, L"status:\t %S\n", data->status);
		fwprintf(fptr, L"thumbprint:\t %S\n", data->thumbprint);
		fwprintf(fptr, L"signAlg:\t %S\n", data->signAlg);
		fwprintf(fptr, L"signType:\t %S\n", data->signType);
		fwprintf(fptr, L"Characteristics:\t %ld\n", data->characteristics);
		fwprintf(fptr, L"Verified:\t %d \n", data->verified);
		fwprintf(fptr, L"isMalwre:\t %d \n", data->isMalware);
		fwprintf(fptr, L"IsMcMalware:\t %d \n", data->mcAnalysis.isMcMalware);
		fwprintf(fptr, L"IsYaraMalware:\t %d \n", data->mcAnalysis.isYaraMalware);
		fwprintf(fptr, L"FeatureConf:\t %f \n", data->mcAnalysis.featureprob);
		fwprintf(fptr, L"ImportConf:\t %f \n", data->mcAnalysis.importprob);
		fwprintf(fptr, L"CombinedConf:\t %f \n", data->mcAnalysis.combineprob);
		fwprintf(fptr, L"ParserVersionCode :\t %S \n", data->parserVersionCode);
		fwprintf(fptr, L"importfunction :\t %S \n", data->importFunctionString);
		fwprintf(fptr, L"cataFile :\t %S \n", data->cataFile);
		fwprintf(fptr, L"patternString :\t %S \n", data->mcAnalysis.patternString);
		fwprintf(fptr, L"patterOffset :\t %zu \n", data->mcAnalysis.patternOffset);
		fwprintf(fptr, L"ErrorCodeStr :\t %S \n", data->errorCodeStr);
		fwprintf(fptr, L"ErrorCode:\t %d \n\n\n", data->errorCode);

		if (fptr) {
			fclose(fptr);
		}
	}
}


__declspec(noinline) void freeImgDetails(struct PEImgDetails* data) {

	data->fileSize = 0;
	if (data->filePath)
		free(data->filePath);
	if (data->publisher)
		free(data->publisher);
	if (data->timeStamp)
		free(data->timeStamp);
	if (data->vSignChainVersion)
		free(data->vSignChainVersion);
	if (data->digestAlgorithm)
		free(data->digestAlgorithm);
	if (data->imphaseHash)
		free(data->imphaseHash);
	if (data->imphashString)
		free(data->imphashString);
	if (data->permission)
		free(data->permission);
	if (data->company)
		free(data->company);
	if (data->product)
		free(data->product);
	if (data->internalName)
		free(data->internalName);
	if (data->copyRights)
		free(data->copyRights);
	if (data->orgFileName)
		free(data->orgFileName);
	if (data->productVersion)
		free(data->productVersion);
	if (data->fileVersion)
		free(data->fileVersion);
	if (data->fileDescription)
		free(data->fileDescription);
	if (data->mimeType)
		free(data->mimeType);
	if (data->fileTypeExt)
		free(data->fileTypeExt);
	if (data->writeTime)
		free(data->writeTime);
	if (data->accessTime)
		free(data->accessTime);
	if (data->createTime)
		free(data->createTime);
	if (data->MD5value)
		free(data->MD5value);
	if (data->SHA1value)
		free(data->SHA1value);
	if (data->SHA256value)
		free(data->SHA256value);
	if (data->SHA512value)
		free(data->SHA512value);
	if (data->status)
		free(data->status);
	if (data->thumbprint)
		free(data->thumbprint);
	if (data->signAlg)
		free(data->signAlg);
	if (data->signType)
		free(data->signType);
	memset(data->fullFeatureArr, 0, sizeof(data->fullFeatureArr));
	memset(data->impFeatureArr, 0, sizeof(data->impFeatureArr));
	data->verified = 0;
	if (data->cataFile)
		free(data->cataFile);
	data->characteristics = 0;
	data->isMalware = -2;
	data->mcAnalysis.combineprob = 0;
	data->mcAnalysis.featureprob = 0;
	data->mcAnalysis.importprob = 0;

	data->mcAnalysis.isYaraMalware = 0;
	data->mcAnalysis.isMcMalware = 0;
	data->errorCode = 0;
	if (data->parserVersionCode) {
		free(data->parserVersionCode);
	}
	if (data->importFunctionString)
		free(data->importFunctionString);
	if (data->filePathW) {
		free(data->filePathW);
	}
	if (data->mcAnalysis.patternString) {
		free(data->mcAnalysis.patternString);
	}
	if (data->errorCodeStr) {
		free(data->errorCodeStr);
	}
	data->mcAnalysis.patternOffset = 0;

	if (data) {
		free(data);
	}
}


__declspec(noinline) void initImgDetails(struct PEImgDetails* data) {
	data->fileSize = 0;
	data->filePath = NULL;
	data->publisher = NULL;
	data->timeStamp = NULL;
	data->vSignChainVersion = NULL;
	data->digestAlgorithm = NULL;
	data->imphaseHash = NULL;
	data->imphashString = NULL;
	data->permission = NULL;
	data->company = NULL;
	data->product = NULL;
	data->internalName = NULL;
	data->copyRights = NULL;
	data->orgFileName = NULL;
	data->productVersion = NULL;
	data->fileVersion = NULL;
	data->fileDescription = NULL;
	data->mimeType = NULL;
	data->fileTypeExt = NULL;
	data->writeTime = NULL;
	data->accessTime = NULL;
	data->createTime = NULL;
	data->MD5value = NULL;
	data->SHA1value = NULL;
	data->SHA256value = NULL;
	data->SHA512value = NULL;
	data->status = NULL;
	data->thumbprint = NULL;
	data->signAlg = NULL;
	data->signType = NULL;
	data->verified = 0;
	data->cataFile = NULL;
	data->characteristics = 0;
	memset(data->fullFeatureArr, 0, sizeof(data->fullFeatureArr));
	memset(data->impFeatureArr, 0, sizeof(data->impFeatureArr));
	data->isMalware = -2;
	data->mcAnalysis.isYaraMalware = 0;
	data->mcAnalysis.isMcMalware = 0;
	data->mcAnalysis.combineprob = 0;
	data->mcAnalysis.featureprob = 0;
	data->mcAnalysis.importprob = 0;
	data->errorCode = 0;
	strDataCopy(&data->parserVersionCode, "V_24_03");
	data->importFunctionString = NULL;
	data->filePathW = NULL;
	data->mcAnalysis.patternString = NULL;
	data->mcAnalysis.patternOffset = 0;
	data->errorCodeStr = NULL;
}


__declspec(noinline) void printAsHex(char* cp, size_t len) {
	return;
	for (size_t i = 0; i < len; i++)
	{
		printf("%02X ", (UINT8)cp[i]);
	}
	printf("\n");
}


__declspec(noinline) void printAsText(char* cp, size_t len) {
	return;
	for (size_t i = 0; i < len; i++)
	{
		printf("%c", (UINT8)cp[i]);
	}
	printf("\n");
}


////////////////////////////////////////////////////////////////////////////// EXTRACT TRUSTED CERTFICATE START ////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////// AVL TREE ////////////////////////////////////////////////////////////////////////////////////


typedef int (*Compare)(const char*, const char*);


__declspec(noinline)  int CmpStr(const char* a, const char* b)
{
	return (strcmp(a, b));
}


__declspec(noinline) Tree_t* createTree() {
	Tree_t* tree = NULL;

	if ((tree = calloc(1, sizeof(Tree_t))) == NULL) {
		return NULL;
	}
	tree->root = NULL;

	return tree;
}


__declspec(noinline) struct Node_t* createNode_t() {
	struct Node_t* node = NULL;
	if ((node = calloc(1, sizeof(struct Node_t))) == NULL) {
		return NULL;
	}
	node->left = NULL;
	node->right = NULL;
	node->key = NULL;
	node->value = NULL;
	return node;
}


__declspec(noinline) int nodeHeight(struct Node_t* node) {
	int height_left = 0;
	int height_right = 0;
	if (node->left) height_left = nodeHeight(node->left);
	if (node->right) height_right = nodeHeight(node->right);
	return height_right > height_left ? ++height_right : ++height_left;
}


__declspec(noinline) int balanceFactor(struct Node_t* node) {
	int bf = 0;

	if (node->left) bf += nodeHeight(node->left);
	if (node->right) bf -= nodeHeight(node->right);

	return bf;
}


__declspec(noinline) struct Node_t* rotateLeftLeft(struct Node_t* node) {
	struct Node_t* a = node;
	struct Node_t* b = a->left;
	a->left = b->right;
	b->right = a;
	return(b);
}


__declspec(noinline) struct Node_t* rotateLeftRight(struct Node_t* node) {
	struct Node_t* a = node;
	struct Node_t* b = a->left;
	struct Node_t* c = b->right;
	a->left = c->right;
	b->right = c->left;
	c->left = b;
	c->right = a;
	return(c);
}


__declspec(noinline) struct Node_t* rotateRightLeft(struct Node_t* node) {
	struct Node_t* a = node;
	struct Node_t* b = a->right;
	struct Node_t* c = b->left;
	a->right = c->left;
	b->left = c->right;
	c->right = b;
	c->left = a;
	return(c);
}


__declspec(noinline) struct Node_t* rotateRightRight(struct Node_t* node) {
	struct Node_t* a = node;
	struct Node_t* b = a->right;

	a->right = b->left;
	b->left = a;

	return(b);
}


__declspec(noinline) struct Node_t* balanceNode(struct Node_t* node) {
	struct Node_t* newroot = NULL;

	if (node->left)
		node->left = balanceNode(node->left);
	if (node->right)
		node->right = balanceNode(node->right);

	int bf = balanceFactor(node);

	if (bf >= 2) {

		if (balanceFactor(node->left) <= -1)
			newroot = rotateLeftRight(node);
		else
			newroot = rotateLeftLeft(node);

	}
	else if (bf <= -2) {

		if (balanceFactor(node->right) >= 1)
			newroot = rotateRightLeft(node);
		else
			newroot = rotateRightRight(node);

	}
	else {

		newroot = node;
	}

	return(newroot);
}


__declspec(noinline) void avlBalance(Tree_t* tree) {

	struct Node_t* newroot = NULL;

	newroot = balanceNode(tree->root);

	if (newroot != tree->root) {
		tree->root = newroot;
	}
}


__declspec(noinline) void avlInsert(Tree_t* tree, char* key, struct Certificate* value) {
	struct Node_t* node = NULL;
	struct Node_t* next = NULL;
	struct Node_t* last = NULL;
	if (tree->root == NULL) {
		node = createNode_t();
		node->key = key;
		node->value = value;
		tree->root = node;
	}
	else {
		next = tree->root;

		while (next != NULL) {
			last = next;

			if (strcmp(key, next->key) < 0) {
				next = next->left;

			}
			else if (strcmp(key, next->key) > 0) {
				next = next->right;

			}
			else if (strcmp(key, next->key) == 0) {
				return;
			}
		}

		node = createNode_t();
		node->key = key;
		node->value = value;
		if (strcmp(key, last->key) < 0) last->left = node;
		if (strcmp(key, last->key) > 0) last->right = node;

	}

	avlBalance(tree);
}


__declspec(noinline) void printNode(struct Node_t* node, char* fmt) {
	int i = 0;

	if (node->left) printNode(node->left, fmt);

	printf(fmt, node->value->Name);

	if (node->right) printNode(node->right, fmt);
}


__declspec(noinline) void avlPrint(Tree_t* tree, char* fmt) {
	//return;
	printNode(tree->root, fmt);
}


__declspec(noinline) struct Node_t* searchNode_t(char* key, struct Node_t* node, Compare cmp)
{
	int res;
	if (node != NULL) {
		res = cmp(key, node->key);
		if (res < 0) {
			return searchNode_t(key, node->left, cmp);
		}
		else if (res > 0) {
			return searchNode_t(key, node->right, cmp);
		}
		else {
			printAsText(node->value->Name, node->value->NameLen);
			return node;
		}
	}
	else {
		return NULL;
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////// AVL TREE END 

__declspec(noinline) int enterTLVCompatibility(char** buffer, char* end, size_t* lSize, float dbgRef) {

	const int data_types[] = {
	MBEDTLS_ASN1_PRINTABLE_STRING,
	MBEDTLS_ASN1_UTF8_STRING,
	MBEDTLS_ASN1_UNIVERSAL_STRING,
	MBEDTLS_ASN1_BMP_STRING,
	MBEDTLS_ASN1_T61_STRING
	};
	const int num_data_types = sizeof(data_types) / sizeof(data_types[0]);

	int ret = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
	for (int i = 0; i < num_data_types; i++) {
		ret = enterTLV(buffer, end, lSize, data_types[i], (float)1.4);
		if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
			break;
		}
	}
	return ret;
}


__declspec(noinline) char* ParseRDNSequence(char* buffer, char* end, size_t lSize, char* oidToFetch, int oidToFetchLen) {
	int ret = 0;
	oidToFetchLen = oidToFetchLen - 1;
	//printf("ParseRDNSequence--Start for %d\n", oidToFetchLen);
	printAsHex(oidToFetch, oidToFetchLen);
	while (enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET, (float)2) >= 0) {
		char* SeqStart = buffer;
		size_t lenSeqStart = lSize;

		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)2.1); RETURN_ON_ERROR(NULL);
		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, (float)2.2); RETURN_ON_ERROR(NULL);


		if (lSize == oidToFetchLen) {
			int i = 0;
			for (; i <= oidToFetchLen; i++) {
				if (buffer[i] != oidToFetch[i]) break;
			}
			if (i != oidToFetchLen) {
				buffer = SeqStart + lenSeqStart;
				continue;
			}
			else {
				//Match for oid found, so return the PrintableString address
				buffer = buffer + lSize;
				return buffer;
			}
		}
		else {
			buffer = SeqStart + lenSeqStart;
			continue;
		}

		ret = enterTLVCompatibility(&buffer, end, &lSize, (float)1.4);
		/*	ret = enterTLV(&issuerName, end, &len, MBEDTLS_ASN1_PRINTABLE_STRING, 1.4);
			if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
				ret = enterTLV(&issuerName, end, &len, MBEDTLS_ASN1_UTF8_STRING, 1.4);
			}*/
		RETURN_ON_ERROR(NULL);

		//ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_PRINTABLE_STRING, 8); RETURN_ON_ERROR(NULL);
		printAsText(buffer, (int)((lSize > 10) ? 10 : lSize));

		buffer = buffer + lSize;
	}
	return NULL;
}


/*
* This api will parse the ASN and pick needed info for cert and return it in cert arg.
*  Certificate  ::=  SEQUENCE  {
		tbsCertificate       TBSCertificate,
		signatureAlgorithm   AlgorithmIdentifier,
		signatureValue       BIT STRING  }

	TBSCertificate  ::=  SEQUENCE  {
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
*/
__declspec(noinline) int  ParseCertificate(char* buffer, char* end, size_t lSize, struct Certificate* cert) {

	//printf("ParseCertificate--Start\n");
	int ret = 0;

	char* start = buffer;
	//for (size_t i = 0; i < lSize; i++)
	//{
	//	printf("%02X ", (UINT8)start[i]);
	//}
	//printf("\n");
	printAsHex(start, lSize);
	calculateHash(MBEDTLS_MD_SHA1, start, lSize, &cert->Thumbprint, &cert->ThumbprintLen);
	//DEBUG//printf("Thumbprint : \n");
	printAsHex(cert->Thumbprint, cert->ThumbprintLen);





	//Enter TBSCertificate
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.0);
	RETURN_ON_ERROR(ret);

	char* tbsCert = buffer;
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.0);
	RETURN_ON_ERROR(ret);
	size_t tbsCertLen = (buffer - tbsCert) + lSize;


	//SKIP SET version [0]
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED, (float)1.1);
	if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
		//DEBUG//printf("Version SET is optional so just skip over and process from next. \n");
	}

	//Get INT :: SerialNumber
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_INTEGER, (float)1.2);
	RETURN_ON_ERROR(ret);
	cert->SerialNumber = buffer;
	cert->SerialNumberLen = (int)lSize;
	buffer = buffer + lSize;


	//Get Algo
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.3); RETURN_ON_ERROR(ret);
	char* algoSeq = buffer;
	size_t algoSeqLen = lSize;
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_OID, (float)1.3); RETURN_ON_ERROR(ret);

	mbedtls_asn1_buf oid;

	oid.tag = MBEDTLS_ASN1_OID;
	oid.p = buffer;
	oid.len = lSize;

	ret = mbedtls_oid_get_md_alg(&oid, &cert->Algorithm);	RETURN_ON_ERROR(ret);
	//printf("Algo Type : %d\n\n", cert->Algorithm);
	buffer = algoSeq + algoSeqLen;


	//Get Issuer Name
	char* tempBuffer = buffer;
	cert->IssuerRDN = buffer;
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1); RETURN_ON_ERROR(ret);
	cert->IssuerRDNLen = (int)((buffer - cert->IssuerRDN) + lSize);
	char* issuerName = ParseRDNSequence(buffer, end, lSize, MBEDTLS_OID_AT_CN, sizeof(MBEDTLS_OID_AT_CN));
	if (issuerName) {
		size_t len = 0;
		ret = enterTLVCompatibility(&issuerName, end, &len, (float)1.4);
		/*	ret = enterTLV(&issuerName, end, &len, MBEDTLS_ASN1_PRINTABLE_STRING, 1.4);
			if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
				ret = enterTLV(&issuerName, end, &len, MBEDTLS_ASN1_UTF8_STRING, 1.4);
			}*/
		RETURN_ON_ERROR(ret);

		cert->IssuerName = issuerName;
		cert->IssuerNameLen = (int)len;
	}
	buffer = tempBuffer;
	skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.4); RETURN_ON_ERROR(ret);
	printAsText(cert->IssuerName, cert->IssuerNameLen);


	//Get Validity time
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.5); RETURN_ON_ERROR(ret);
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_UTC_TIME, 1.5);
	if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_GENERALIZED_TIME, 1.5);
	}
	RETURN_ON_ERROR(ret);
	cert->ValidFrom = buffer;
	cert->ValidFromLen = (int)lSize;
	buffer = buffer + lSize;
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_UTC_TIME, 1.5);
	if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
		ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_GENERALIZED_TIME, 1.5);
	}
	RETURN_ON_ERROR(ret);
	cert->ValidTo = buffer;
	cert->ValidToLen = (int)lSize;
	buffer = buffer + lSize;


	//Get Cert Name
	tempBuffer = buffer;
	cert->SubjectRDN = buffer;
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1); RETURN_ON_ERROR(ret);
	cert->SubjectRDNLen = (int)((buffer - cert->SubjectRDN) + lSize);
	char* name = ParseRDNSequence(buffer, end, lSize, MBEDTLS_OID_AT_CN, sizeof(MBEDTLS_OID_AT_CN));
	if (name) {
		size_t len = 0;

		ret = enterTLVCompatibility(&name, end, &len, (float)1.4);
		/*ret = enterTLV(&name, end, &len, MBEDTLS_ASN1_PRINTABLE_STRING, 1.4);
		if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
			ret = enterTLV(&name, end, &len, MBEDTLS_ASN1_UTF8_STRING, 1.4);
		}*/
		RETURN_ON_ERROR(ret);
		cert->Name = name;
		cert->NameLen = (int)len;
	}
	buffer = tempBuffer;
	skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.4); RETURN_ON_ERROR(ret);
	printAsText(cert->Name, cert->NameLen);

	//Enter SubjectPublicKeyInfo SEQUENCE
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.5); RETURN_ON_ERROR(ret);


	//Skip SubjectPublicKeyInfo->Algo SEQUENCE
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.6); RETURN_ON_ERROR(ret);


	//Enter SubjectPublicKeyInfo->subjectPublicKey BITSTRING
	ret = mbedtls_asn1_get_bitstring_null(&buffer, end, &lSize); RETURN_ON_ERROR(ret);


	//Enter SubjectPublicKeyInfo->subjectPublicKey SEQUENCE
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.7); RETURN_ON_ERROR(ret);


	//Get PublicKey INT
	ret = enterTLV(&buffer, end, &lSize, MBEDTLS_ASN1_INTEGER, (float)1.8); RETURN_ON_ERROR(ret);
	cert->SubjectPublicKeyInfo = buffer;
	cert->SubjectPublicKeyInfoLen = (int)lSize;
	buffer = buffer + lSize;

	//Get Exponent INT
	ret = mbedtls_asn1_get_int(&buffer, end, &(cert->SubjectPublicKeyExponent));


	printAsHex(tbsCert, tbsCertLen);

	//End of tbscert, now calculate hash for future usage
	calculateHash(cert->Algorithm, tbsCert, tbsCertLen, &cert->tbsCertHashValue, &cert->tbsCertHashValueLen);
	//DEBUG//printf("Thumbprint : \n");
	printAsHex(cert->tbsCertHashValue, cert->tbsCertHashValueLen);


	//skip tbscert
	buffer = tbsCert + tbsCertLen;

	//skip algo
	ret = skipTLV(&buffer, end, &lSize, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, (float)1.0);
	RETURN_ON_ERROR(ret);

	ret = mbedtls_asn1_get_bitstring_null(&buffer, end, &lSize);
	//DEBUG//printf("BITSTRING  Returned %x ->  Buffer %p  Len %d  and End %p\n", ret < 0 ? -(unsigned)ret : ret, buffer, lSize, end);

	cert->SignatureValue = buffer;
	cert->SignatureValueLen = (int)lSize;


	//DEBUG//printf("ParseCertificate--End\n");

	return ret;
}




__declspec(noinline) void printCertificate(struct Certificate* cert) {
	return;
	printf("ParsedCertificate Details :\n");
	printf("Name :");
	printAsText(cert->Name, cert->NameLen);
	printf("SubjectRDN :");
	printAsHex(cert->SubjectRDN, cert->SubjectRDNLen);
	printf("Issuer :");
	printAsText(cert->IssuerName, cert->IssuerNameLen);
	printf("IssuerRDN :");
	printAsHex(cert->IssuerRDN, cert->IssuerRDNLen);
	printf("Thumbprint :");
	printAsHex(cert->Thumbprint, cert->ThumbprintLen);
	printf("SerialNumber :");
	printAsHex(cert->SerialNumber, cert->SerialNumberLen);
	printf("Algorithm : %d\n", cert->Algorithm);
	printf("Public Key :");
	printAsHex(cert->SubjectPublicKeyInfo, cert->SubjectPublicKeyInfoLen);
	printf("Public Key Exponent: %d\n\n\n", cert->SubjectPublicKeyExponent);

}

/*
 * Delete middle Certificate of the linked list
 */
__declspec(noinline) void deleteMiddleCertificate(struct Certificate* head, int position)
{
	int i;
	struct Certificate* toDelete, * prevCertificate;

	if (head == NULL)
	{
		//DEBUG//printf("List is already empty.");
	}
	else
	{
		toDelete = head;
		prevCertificate = head;

		for (i = 2; i <= position; i++)
		{
			prevCertificate = toDelete;
			toDelete = toDelete->next;

			if (toDelete == NULL)
				break;
		}

		if (toDelete != NULL)
		{
			if (toDelete == head)
				head = head->next;

			prevCertificate->next = toDelete->next;
			toDelete->next = NULL;

			/* Delete nth Certificate */
			free(toDelete);

			//DEBUG//printf("SUCCESSFULLY DELETED Certificate FROM MIDDLE OF LIST\n");
		}
		else
		{
			//DEBUG//printf("Invalid position unable to delete.");
		}
	}
}


struct SystemCertificate {
	int propid;
	int unknown;
	int size;
	char array;
};


__declspec(noinline) void ReadRegValue(HKEY root, wchar_t* key, wchar_t* name, Tree_t* TrustedCAtree)
{

	HKEY hKey;
	//DEBUG//printf("\n%ws %ws \n\n", key, name);
	if (RegOpenKeyEx(root, key, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
		//DEBUG//printf("Unable to open key %d\n", GetLastError());
		return;
	}

	DWORD dwBufSize = 1000;
	char* certData = calloc(dwBufSize, sizeof(char));
	DWORD error;
	do {
		free(certData);
		certData = calloc(dwBufSize, sizeof(char));
		error = RegQueryValueEx(hKey, name, NULL, NULL, certData, &dwBufSize);

	} while (error == ERROR_MORE_DATA);


	if (error == ERROR_SUCCESS)
	{
		char* certEnd = certData + dwBufSize;

		struct SystemCertificate* cert = (struct SystemCertificate*)certData;
		while (cert && (char*)cert < certEnd) {
			////DEBUG//printf("Cert : %2x\n", cert->propid);
			if (cert->propid == 0x20) {				//Constant value used for cert refer wincrypt.h  and look for CertSetCertificateContextProperty in comments
				struct Certificate* parsedCert = (struct Certificate*)calloc(1, sizeof(struct Certificate));
				if (parsedCert) {
					int ret = ParseCertificate(&(cert->array), certEnd, cert->size, parsedCert);
					if (ret >= 0) {
						persistCharArray(&parsedCert->IssuerName, parsedCert->IssuerNameLen);
						persistCharArray(&parsedCert->IssuerRDN, parsedCert->IssuerRDNLen);
						persistCharArray(&parsedCert->Name, parsedCert->NameLen);
						persistCharArray(&parsedCert->SubjectRDN, parsedCert->SubjectRDNLen);
						persistCharArray(&parsedCert->SerialNumber, parsedCert->SerialNumberLen);
						persistCharArray(&parsedCert->SignatureValue, parsedCert->SignatureValueLen);
						persistCharArray(&parsedCert->SubjectPublicKeyInfo, parsedCert->SubjectPublicKeyInfoLen);
						//printf("%s \t %s\n", parsedCert->Name,parsedCert->SubjectRDN);
						//persistCharArray(&parsedCert->tbsCertHashValue, parsedCert->tbsCertHashValueLen);
						//persistCharArray(&parsedCert->Thumbprint, parsedCert->ThumbprintLen); // lastUpdate 
						printCertificate(parsedCert);
						char* name = (char*)calloc(((parsedCert->SubjectRDNLen) + 1), sizeof(char));
						if (name) {
							memcpy(name, parsedCert->SubjectRDN, parsedCert->SubjectRDNLen);
							//DEBUG//printf("\nName is : %s\n", name);
							avlInsert(TrustedCAtree, name, parsedCert);
						}

					}
					else {
						/*printf("###########################################ERROR####################################\n");
						printAsHex(&cert->array, cert->size);

						for (size_t i = 0; i < cert->size; i++)
						{
							printf("%02X ", (UINT8)*(&cert->array + i));
						}
						printf("\n");
						printf("###########################################ERROR####################################\n");*/

					}
				}
				break;
			}
			else {
				cert = (struct SystemCertificate*)(&(cert->array) + cert->size);
			}
		}

	}
	else
	{
		//printf("Cannot read key %ws\n", key);
	}
	RegCloseKey(hKey);

	free(certData);
}


__declspec(noinline) int enumSubKeysAndParseCert(TCHAR* basestr, Tree_t* TrustedCAtree) {
	HKEY hk;
	LONG ret;
	DWORD i;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, basestr, 0, KEY_ENUMERATE_SUB_KEYS,
		&hk);
	if (ret != ERROR_SUCCESS)
		return EXIT_FAILURE;
	for (i = 0; ; i++) {
		TCHAR name[255];
		DWORD namelen;

		namelen = 255;
		ret = RegEnumKeyEx(hk, i, name, &namelen, NULL, NULL, NULL,
			NULL);

		if (ret == ERROR_NO_MORE_ITEMS)
			break;

		if (ret != ERROR_SUCCESS) {
			printf("TNC: RegEnumKeyEx failed: 0x%x",
				(unsigned int)ret);
			break;
		}
		wchar_t* childkeyPath = NULL;
		if (basestr) {
			childkeyPath = calloc(((lstrlenW(basestr) + namelen + 1) * 2), sizeof(char));
			if (childkeyPath != NULL) ZeroMemory(childkeyPath, lstrlenW(basestr) + namelen + 2);
		}
		int j = 0;
		if (basestr != NULL) {
			for (; j < lstrlenW(basestr); j++) {
				if (childkeyPath != NULL) childkeyPath[j] = basestr[j];
			}
			for (; j < lstrlenW(basestr) + (int)namelen; j++) {
				if (childkeyPath != NULL) childkeyPath[j] = name[j - lstrlenW(basestr)];
			}
		}
		if (childkeyPath)
			childkeyPath[j] = '\0';


		//DEBUG//printf("\n%ws\n", childkeyPath);
		ReadRegValue(HKEY_LOCAL_MACHINE, childkeyPath, L"Blob", TrustedCAtree);
		free(childkeyPath);

		//DEBUG//printf("\n");
	}
	return EXIT_SUCCESS;
}


__declspec(noinline) int prepareAuthCertsFromRegistry(Tree_t* TrustedCAtree) {
	TCHAR* AuthRootStr = (TCHAR*)L"SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\";
	TCHAR* RootStr = (TCHAR*)L"SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\";
	TCHAR* pRoot = (TCHAR*)L"SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\";
	TCHAR* pCurrentUserTrustedPublisher = (TCHAR*)L"Software\\Microsoft\\SystemCertificates\\TrustedPublisher\\Certificates\\";
	enumSubKeysAndParseCert(AuthRootStr, TrustedCAtree);
	enumSubKeysAndParseCert(RootStr, TrustedCAtree);
	enumSubKeysAndParseCert(pRoot, TrustedCAtree);
	enumSubKeysAndParseCert(pCurrentUserTrustedPublisher, TrustedCAtree);
	/*
	wprintf(L"winTrustedCertificatesPath: %s\n", winTrustedCertificatesPath);
	if (winTrustedCertificatesPath != NULL) {

		FILE* fp = NULL;
		errno_t err = _wfopen_s(&fp, winTrustedCertificatesPath, L"rb");
		if (fp != NULL) {
			rewind(fp);
			while (1) {
				struct regData data;
				if (fread(&data, sizeof(struct regData), 1, fp)) {
					//printf("%d\n", data.size);
					char* certData = data.data;

					char* certEnd = certData + data.size;

					struct SystemCertificate* cert = (struct SystemCertificate*)certData;
					while (cert && cert < (struct SystemCertificate*)certEnd) {
						////DEBUG//printf("Cert : %2x\n", cert->propid);
						if (cert->propid == 0x20) {				//Constant value used for cert refer wincrypt.h  and look for CertSetCertificateContextProperty in comments
							struct Certificate* parsedCert = (struct Certificate*)calloc(1, sizeof(struct Certificate));
							if (parsedCert) {
								ZeroMemory(parsedCert, sizeof(struct Certificate));
								int ret = ParseCertificate(&(cert->array), certEnd, cert->size, parsedCert);
								if (ret >= 0) {
									persistCharArray(&parsedCert->IssuerName, parsedCert->IssuerNameLen);
									persistCharArray(&parsedCert->IssuerRDN, parsedCert->IssuerRDNLen);
									persistCharArray(&parsedCert->Name, parsedCert->NameLen);
									persistCharArray(&parsedCert->SubjectRDN, parsedCert->SubjectRDNLen);
									persistCharArray(&parsedCert->SerialNumber, parsedCert->SerialNumberLen);
									persistCharArray(&parsedCert->SignatureValue, parsedCert->SignatureValueLen);
									persistCharArray(&parsedCert->SubjectPublicKeyInfo, parsedCert->SubjectPublicKeyInfoLen);
									//persistCharArray(&parsedCert->tbsCertHashValue, parsedCert->tbsCertHashValueLen);
									//persistCharArray(&parsedCert->Thumbprint, parsedCert->ThumbprintLen); // lastUpdate 

									// printf("%s \n", parsedCert->Name);
									// for (size_t i = 0; i < parsedCert->SubjectRDNLen; i++)
								 	// {
									// 	printf("%02X ", (UINT8)parsedCert->SubjectRDN[i]);
									// }
									// printf("\n");
									printCertificate(parsedCert);

									char* name = (char*)calloc(((parsedCert->SubjectRDNLen) + 1), sizeof(char));
									if (name) {
										ZeroMemory(name, (int)parsedCert->SubjectRDNLen + 1);
										memcpy(name, parsedCert->SubjectRDN, parsedCert->SubjectRDNLen);
										//DEBUG//printf("\nName is : %s\n", name);
										avlInsert(TrustedCAtree, name, parsedCert);
									}
								}
								else {
									//DEBUG//printf("###########################################ERROR####################################\n");
									printAsHex(&cert->array, cert->size);
									//DEBUG//printf("###########################################ERROR####################################\n");

								}
							}
							break;
						}
						else {
							cert = (struct SystemCertificate*)(&(cert->array) + cert->size);
						}
					}

				}
				else {
					break;
				}
			}
			if (fp) {
				fclose(fp);
				fp = NULL;
			}
		}
		else {
			// printf("INFO:\tDefault Cert Missing\n\n");
		}

		}
	*/

	return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////// EXTRACT TRUSTED CERTFICATE END ////////////////////////////////////////////////////////////////////////////////////


__declspec(noinline) void GetFileDetail(wchar_t* filepath, struct ExtNode* root, struct PEImgDetails* data, Tree_t* TrustedCAtree, FILE* fp) {


	if (root == NULL || TrustedCAtree == NULL) {
		printf("Init Not Configure Properly ");
	}

	//file permission , create time, access time;	
	filePermission(data);
	if (data->fileSize == 0)
		goto cleanup;
	//sha256 sha1 md5 sha512  CompanyName FileDescription FileVersion InternalName LegalCopyright OriginalFilename ProductName ProductVersion VarFileInfo Embeded Catlog Detail of the file	
	hashDetail(data, root, TrustedCAtree, fp);
	if (data->cataFile) {
		char CataFileStr[1000];
		convertFilePath(data->cataFile, CataFileStr);
		free(data->cataFile);
		strDataCopy(&data->cataFile, CataFileStr);
	}
	if (data->filePath) {
		char filePathStr[1000];
		convertFilePath(data->filePath, filePathStr);
		free(data->filePath);
		strDataCopy(&data->filePath, filePathStr);
	}

	if (data->timeStamp) {
		char timeStampStr[1000];
		convertFilePath(data->timeStamp, timeStampStr);
		free(data->timeStamp);
		strDataCopy(&data->timeStamp, timeStampStr);
	}

	strDataCopy(&data->status, "SUCCESS");
	return;
cleanup:
	data->errorCode = FILE_SIZE_ZERO;
	strDataCopy(&data->status, "FAILED");
	return;
}


__declspec(noinline) void importFuncToFeatureArray(struct FeatNode* head, float* featarray, struct hashTableMalwareFullFunc* mapMalwareFullFunc) {
	struct FeatNode* tmp = head;
	int retrieveMalwareFullFuncRet = 0;
	while (tmp != NULL) {
		//printf("%s \t", tmp->key);
		retrieveMalwareFullFuncRet = retrieveMalwareFullFunc(mapMalwareFullFunc, (char*)strlwr(tmp->key));
		//printf("%d\n", retrieveMalwareFullFuncRet);
		if (retrieveMalwareFullFuncRet != -1) {
			featarray[retrieveMalwareFullFuncRet] = 1;
		}

		tmp = tmp->next;
	}

}


// if success return 1 else return false. Module collect the certificate from Registry and ext/mimetype from predefined. 
__declspec(noinline) int initPEParser(wchar_t* patternRulePath) {
	
	int32_t retStatus = EXIT_SUCCESS;

	if (fileParserTreeData.TrustedCAtree == NULL) {
		fileParserTreeData.TrustedCAtree = createTree();
		prepareAuthCertsFromRegistry(fileParserTreeData.TrustedCAtree);
	}

	if(fileParserTreeData.root == NULL){
		fileParserTreeData.root = createNodeTrie(0, NULL);
		initTriavllist(fileParserTreeData.root);
	}

	if (fileParserTreeData.mapMalwareFullFunc == NULL) {
		fileParserTreeData.mapMalwareFullFunc = (struct hashTableMalwareFullFunc*)calloc(1, sizeof(struct hashTableMalwareFullFunc));
		InitMalwareFullFunc(fileParserTreeData.mapMalwareFullFunc);
	}
	
	if (fileParserTreeData.TrustedCAtree == NULL || fileParserTreeData.root == NULL || fileParserTreeData.mapMalwareFullFunc == NULL) {
		printf("InitFailed To Parser \n");
		retStatus = EXIT_FAILURE;
		return retStatus;
	}
	else {
		retStatus = EXIT_SUCCESS;
	}

	if (patternRulePath != NULL && *patternRulePath != L'\0') {
		retStatus =  initRuleEngineInternal(patternRulePath);
	}

	//DEBUG SEARCH AVL CERT LIST
	//avlPrint(TrustedCAtree, "Key : %s \n");
	//Node_t* n = search("USERTrust RSA Certification Authority", (*TrustedCAtree)->root, (Compare)CmpStr);
	//if (n == NULL) {
	//	//DEBUG//printf("Cert not found in AVL\n");
	//}
	//else {
	//	//DEBUG//printf("Cert found in AVL :)\n");
	//	printCertificate(n->value);
	//}
	return retStatus;
}





void scanWrapper(ScannerConfig* malDetEngine, struct PEImgDetails* data, LPVOID fp) {
	if (data != NULL) {
		data->isMalware = MC_BENIGN;
		data->mcAnalysis.isMcMalware = MC_BENIGN;
		data->mcAnalysis.isYaraMalware = MC_BENIGN;

		// MC - SCAN
		if (malDetEngine->mcScanFlag == 1) {
			OnnxToCConversion(data);
		}

		// YARA - SCAN 
		if (malDetEngine->yaraScanFlag == 1) {
			if (fp != NULL) {
				scanRuleEngine(data, fp);
			}
		}

		if (data->mcAnalysis.isMcMalware == MC_MALWARE || data->mcAnalysis.isYaraMalware == MC_MALWARE) {
			data->isMalware = MC_MALWARE;
		}
	}

}

void peImgDetailsAdjustment(struct PEImgDetails* data) {

	if (data && data->company != NULL && !(strlen(data->company) <= 3) && data->fullFeatureArr[263] == 0 && data->verified != 1) {
		char* companyNameD = (char*)malloc((strlen(data->company) + 1) * (sizeof(char)));
		if (companyNameD) {
			memset(companyNameD, 0, strlen(data->company) + 1);
			memcpy(companyNameD, data->company, strlen(data->company));
			if (strstr(strlwr(companyNameD), "microsoft") != NULL) {
				for (int i = 0; i < 100; i++) {
					data->fullFeatureArr[2023 + i] = 0;
					data->fullFeatureArr[2123 + i] = 0;
				}
			}
			free(companyNameD);
		}
	}
	if(data)
	{
		data->fullFeatureArr[276] = 0; // dll_characteristics
		//File magic - 306 to 315 
		for (int i = 0; i <= 9; i++) {
			data->fullFeatureArr[306 + i] = 0;
		}
		//Publisher hash - 2123 to 2222
		for (int i = 0; i <= 90; i++) {
			data->fullFeatureArr[2123 + i] = 0;
		}
	}
}

__declspec(noinline) struct PEImgDetails* PEFileScanner(wchar_t* baseDir, ScannerConfig* malDetEngine) {

	struct PEImgDetails* data = NULL;

	HANDLE fileHandle = CreateFileW(
		baseDir,                    // File path
		GENERIC_READ,               // Open for reading
		FILE_SHARE_READ,            // Share for reading
		NULL,                       // Default security
		OPEN_EXISTING,              // Only open if file exists
		FILE_FLAG_SEQUENTIAL_SCAN,  // Optimization flag for sequential access
		NULL                        // No template file
	);

	if (fileHandle != INVALID_HANDLE_VALUE)
	{

		HANDLE mappingHandle = CreateFileMapping(
			fileHandle,
			NULL,
			PAGE_READONLY,
			0,
			0,
			NULL
		);
		if (mappingHandle == NULL) {
			printf("Error creating file mapping\n");
			CloseHandle(fileHandle);
			return data;
		}
		LPVOID mappedView = MapViewOfFile(
			mappingHandle,
			FILE_MAP_READ,
			0,
			0,
			0
		);
		if (mappedView == NULL) {
			printf("Error mapping view of file\n");
			CloseHandle(mappingHandle);
			CloseHandle(fileHandle);
			return data;
		}

		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)mappedView;
		if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
			data = startPE(baseDir, malDetEngine, mappedView);

			// data adjustment
			peImgDetailsAdjustment(data);

			// scanning function 
			scanWrapper(malDetEngine, data, mappedView);
		}

		if (mappedView != NULL) {
			UnmapViewOfFile(mappedView);
			mappedView = NULL;
		}

		if (mappingHandle != NULL && mappingHandle != INVALID_HANDLE_VALUE) {
			CloseHandle(mappingHandle);
			mappingHandle = NULL;
		}

		if (fileHandle != NULL && fileHandle != INVALID_HANDLE_VALUE) {
			CloseHandle(fileHandle);
			fileHandle = NULL;
		}
	}

	return data;
}

__declspec(noinline) struct PEImgDetails* startPE(wchar_t* str, ScannerConfig* malDetEngine, LPVOID mappedView) {
	//printf("%s ", str);
	_ASSERTE(_CrtCheckMemory());
	struct PEImgDetails* data = NULL;
	corruptedField = 0;

	if (mappedView != NULL && str != NULL && *str != '\0') {

		data = (struct PEImgDetails*)calloc(1, sizeof(struct PEImgDetails));
		if (data == NULL) {
			return NULL;
		}
		initImgDetails(data);
		wstrDataCopy(&data->filePathW, str);
		strDataCopy(&data->filePath, wStringToString(data->filePathW));
		GetFileDetail(str, fileParserTreeData.root, data, fileParserTreeData.TrustedCAtree, mappedView);

		// Collect Feature Array Details
		struct FeatNode* importFunNameListFeatureExtractor = NULL;
		if (data) {
			int isExe = 1;
			importFunNameListFeatureExtractor = collectMC(mappedView, data, &isExe);
			data->fullFeatureArr[2223] = (float)corruptedField;
			if (isExe == 0) {
				freeImgDetails(data);
				
				return NULL;
			}

		}
		if (data) {
			if (fileParserTreeData.mapMalwareFullFunc != NULL) {
				importFuncToFeatureArray(importFunNameListFeatureExtractor, data->impFeatureArr, fileParserTreeData.mapMalwareFullFunc);
				if (importFunNameListFeatureExtractor) {
					freeFeatNode(importFunNameListFeatureExtractor);
				}
			}
			else {
				printf("Init Not Configure Properly ");
			}
		}

		float companyHashArray[100] = { 0 };
		float publisherHashArray[100] = { 0 };
		struct FeatNode* company = NULL;
		struct FeatNode* publisher = NULL;

		// data set for company and publisher
		if (data && data->company != NULL && !(strlen(data->company) <= 3)) {
			data->fullFeatureArr[2020] = 1;
			/* Hashing first 6 characters of company */
			char* comp = data->company;
			char compSubstr[7];
			memcpy(compSubstr, &comp[0], 6);
			compSubstr[6] = '\0';
			searchInsertFeatNode(&company, compSubstr, 1.0);
			featureHasher(company, 100, companyHashArray);
		}
		else {
			if (data)
				data->fullFeatureArr[2020] = 0;
		}
		if (data && data->publisher != NULL && !(strlen(data->publisher) <= 3)) {
			data->fullFeatureArr[2021] = 1;
			/* Hashing first 6 characters of publisher */
			char* pub = data->publisher;
			char pubSubstr[7];
			memcpy(pubSubstr, &pub[0], 6);
			pubSubstr[6] = '\0';
			searchInsertFeatNode(&publisher, pubSubstr, 1.0);
			featureHasher(publisher, 100, publisherHashArray);
		}
		else {
			if (data)
				data->fullFeatureArr[2021] = 0;
		}
		if (company)
			freeFeatNode(company);
		if (publisher)
			freeFeatNode(publisher);
		if (data) {
			for (int i = 0; i < 100; i++) {
				data->fullFeatureArr[2023 + i] = companyHashArray[i];
				data->fullFeatureArr[2123 + i] = publisherHashArray[i];
			}

			if (data->verified) {
				data->fullFeatureArr[2022] = 1;
			}
			else {
				data->fullFeatureArr[2022] = 0;
			}
		}


	}
	else {
		printf("File pointer NULL Found \n");
		return NULL;
	}
	_CrtCheckMemory();
	_CrtDumpMemoryLeaks();
	return data;

}


__declspec(noinline) int getAllFilesFileParserW(WCHAR* rootDir, BOOL subDirectories, ScannerConfig* malDetEngine, int printDetails) {
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	BOOL bSubdirectory = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FileInformation;
	size_t strPatternLen = wcslen(rootDir) + 6;
	WCHAR* strPattern = (WCHAR*)calloc(strPatternLen, sizeof(WCHAR));

	if (strPattern == NULL) {
		wprintf(L"Memory allocation failed for strPattern\n");
		return EXIT_FAILURE;
	}
	wcscpy_s(strPattern, strPatternLen, rootDir);
	wcscat_s(strPattern, strPatternLen, L"\\*.*");

	hFile = FindFirstFileW(strPattern, &FileInformation);
	if (hFile == INVALID_HANDLE_VALUE) {
		//wprintf(L"FindFirstFileW failed for pattern %s\n", strPattern);
		free(strPattern);
		return EXIT_FAILURE;
	}

	do {
		if (FileInformation.cFileName[0] != '.') {
			size_t strFilePathLen = wcslen(rootDir) + wcslen(FileInformation.cFileName) + 3;
			WCHAR* strFilePath = (WCHAR*)calloc(strFilePathLen, sizeof(WCHAR));

			if (strFilePath == NULL) {
				wprintf(L"Memory allocation failed for strFilePath\n");
				FindClose(hFile);
				free(strPattern);
				return EXIT_FAILURE;
			}

			wcscpy_s(strFilePath, strFilePathLen, rootDir);
			wcscat_s(strFilePath, strFilePathLen, L"\\");
			wcscat_s(strFilePath, strFilePathLen, FileInformation.cFileName);

			if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (subDirectories) {
					getAllFilesFileParserW(strFilePath, subDirectories, malDetEngine, printDetails);
				}
				else {
					bSubdirectory = TRUE;
				}
			}
			else {

				HANDLE fileHandle = CreateFileW(
					strFilePath,                    // File path
					GENERIC_READ,               // Open for reading
					FILE_SHARE_READ,            // Share for reading
					NULL,                       // Default security
					OPEN_EXISTING,              // Only open if file exists
					FILE_FLAG_SEQUENTIAL_SCAN,  // Optimization flag for sequential access
					NULL                        // No template file
				);


				if (fileHandle != INVALID_HANDLE_VALUE) {
					HANDLE mappingHandle = CreateFileMapping(
						fileHandle,
						NULL,
						PAGE_READONLY,
						0,
						0,
						NULL
					);
					if (mappingHandle != NULL) {

						LPVOID mappedView = MapViewOfFile(
							mappingHandle,
							FILE_MAP_READ,
							0,
							0,
							0
						);
						if (mappedView != NULL) {

							IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)mappedView;

							if (23117 == (int)DosHeader->e_magic) {
								_ASSERTE(_CrtCheckMemory());
								struct PEImgDetails* img = startPE(strFilePath, malDetEngine, mappedView);
								wprintf(L"%s\n", strFilePath);
								if (img != NULL) {
									printImgDetails(img, 1);
									freeImgDetails(img);
									free(img);
								}
								if (!_CrtCheckMemory()) {
									_CrtDumpMemoryLeaks();
								}
								_CrtDumpMemoryLeaks();
							}

							if (mappedView != NULL) {
								UnmapViewOfFile(mappedView);
								mappedView = NULL;
							}

							if (mappingHandle != NULL && mappingHandle != INVALID_HANDLE_VALUE) {
								CloseHandle(mappingHandle);
								mappingHandle = NULL;
							}

							if (fileHandle != NULL && fileHandle != INVALID_HANDLE_VALUE) {
								CloseHandle(fileHandle);
								fileHandle = NULL;
							}

						}
						else {
							wprintf(L"Error mapping view of file: %s\n", strFilePath);
							CloseHandle(mappingHandle);
							CloseHandle(fileHandle);
						}
					}
					else {
						wprintf(L"Failed to create file mapping: %s\n", strFilePath);
						CloseHandle(fileHandle);
					}
				}
				else {
					wprintf(L"Failed to open file: %s\n", strFilePath);
				}
			}
			free(strFilePath);
		}
	} while (FindNextFileW(hFile, &FileInformation) == TRUE);

	FindClose(hFile);
	free(strPattern);

	return EXIT_SUCCESS;
}


__declspec(noinline) int getAllFilesFileParser(const char* rootDir, BOOL subDirectories, ScannerConfig* malDetEngine, int printDetails) {
	wchar_t* rootDirW;
	strToWstr(&rootDirW, rootDir);
	return getAllFilesFileParserW(rootDirW, subDirectories, malDetEngine, printDetails);
}

int FPSha256Calculation(const wchar_t* filepath, char* HashValue) {
	BCRYPT_ALG_HANDLE algHandle = NULL;
	BCRYPT_HASH_HANDLE hashHandle = NULL;
	BYTE* hashObject = NULL;
	BYTE hashBuffer[32];
	BYTE* fileBuffer = NULL;
	DWORD hashObjectLength = 0, resultLength = 0;
	DWORD bytesRead = 0;
	int status = EXIT_FAILURE;

	FILE* fp = NULL;

	// Open the file for reading
	if (_wfopen_s(&fp, filepath, L"rb") != 0 || fp == NULL) {
		wprintf(L"Error: Unable to open file.\n");
		return status;
	}

	// Dynamically allocate memory for fileBuffer
	fileBuffer = (BYTE*)malloc(BUFSIZE);
	if (!fileBuffer) {
		wprintf(L"Memory allocation failed for file buffer.\n");
		fclose(fp);
		return status;
	}

	// Open SHA-256 algorithm provider
	NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptOpenAlgorithmProvider failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Get the length of the hash object
	ntStatus = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectLength, sizeof(DWORD), &resultLength, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptGetProperty (BCRYPT_OBJECT_LENGTH) failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}
	// Allocate memory for the hash object
	hashObject = (BYTE*)malloc(hashObjectLength);
	if (!hashObject) {
		wprintf(L"Memory allocation failed for hash object.\n");
		goto Cleanup;
	}

	// Create a hash
	ntStatus = BCryptCreateHash(algHandle, &hashHandle, hashObject, hashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptCreateHash failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Read file in chunks and hash the data
	while ((bytesRead = (DWORD)fread(fileBuffer, 1, BUFSIZE, fp)) > 0) {
		ntStatus = BCryptHashData(hashHandle, fileBuffer, bytesRead, 0);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"BCryptHashData failed: 0x%x\n", ntStatus);
			goto Cleanup;
		}
	}

	// Finalize the hash
	ntStatus = BCryptFinishHash(hashHandle, hashBuffer, 32, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptFinishHash failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Convert hash to hexadecimal string
	for (DWORD i = 0; i < 32; ++i) {
		sprintf(&HashValue[i * 2], "%02X", hashBuffer[i]);
	}

	status = EXIT_SUCCESS;

Cleanup:
	if (fp) fclose(fp);
	if (fileBuffer) free(fileBuffer);
	if (hashHandle) BCryptDestroyHash(hashHandle);
	if (hashObject) free(hashObject);
	if (algHandle) BCryptCloseAlgorithmProvider(algHandle, 0);

	return status;
}


int FPSha256CalculationWithHandle(BCRYPT_ALG_HANDLE algHandle1, const wchar_t* filepath, char* HashValue) {
	BCRYPT_HASH_HANDLE hashHandle = NULL;
	BYTE* hashObject = NULL;
	BYTE hashBuffer[32];
	BYTE* fileBuffer = NULL;
	DWORD hashObjectLength = 0, resultLength = 0;
	DWORD bytesRead = 0;
	int status = EXIT_FAILURE;

	FILE* fp = NULL;

	// Open the file for reading
	if (_wfopen_s(&fp, filepath, L"rb") != 0 || fp == NULL) {
		wprintf(L"Error: Unable to open file.\n");
		return status;
	}

	// Dynamically allocate memory for fileBuffer
	fileBuffer = (BYTE*)malloc(BUFSIZE);
	if (!fileBuffer) {
		wprintf(L"Memory allocation failed for file buffer.\n");
		fclose(fp);
		return status;
	}

	// Open SHA-256 algorithm provider
	NTSTATUS ntStatus;

	// Get the length of the hash object
	ntStatus = BCryptGetProperty(algHandle1, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectLength, sizeof(DWORD), &resultLength, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptGetProperty (BCRYPT_OBJECT_LENGTH) failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Allocate memory for the hash object
	hashObject = (BYTE*)malloc(hashObjectLength);
	if (!hashObject) {
		wprintf(L"Memory allocation failed for hash object.\n");
		goto Cleanup;
	}

	// Create a hash
	ntStatus = BCryptCreateHash(algHandle1, &hashHandle, hashObject, hashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptCreateHash failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Read file in chunks and hash the data
	while ((bytesRead = (DWORD)fread(fileBuffer, 1, BUFSIZE, fp)) > 0) {
		ntStatus = BCryptHashData(hashHandle, fileBuffer, bytesRead, 0);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"BCryptHashData failed: 0x%x\n", ntStatus);
			goto Cleanup;
		}
	}

	// Finalize the hash
	ntStatus = BCryptFinishHash(hashHandle, hashBuffer, 32, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptFinishHash failed: 0x%x\n", ntStatus);
		goto Cleanup;
	}

	// Convert hash to hexadecimal string
	for (DWORD i = 0; i < 32; ++i) {
		sprintf(&HashValue[i * 2], "%02X", hashBuffer[i]);
	}

	status = EXIT_SUCCESS;

Cleanup:
	if (fp) fclose(fp);
	if (fileBuffer) free(fileBuffer);
	if (hashHandle) BCryptDestroyHash(hashHandle);
	if (hashObject) free(hashObject);

	return status;
}

