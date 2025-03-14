#include <iostream>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

extern "C"
{
#include "FileParser.h"
#include "FeatureExtractor/FeatureHeader.h"

}

int fileCount = 0;
struct SystemCertificate {
	int propid;
	int unknown;
	int size;
	char array;
};



void getData2(WCHAR* CataFile) {
	GenericLL* SignChain = NULL;
	//GetSignerCertificateInfo(CataFile, &SignChain);
	CERT_NODE_INFO* tmpValue1 = NULL;
	SIGN_NODE_INFO* tmpValue = NULL;
	char* timesStamp = NULL;
	char* publisher = NULL;
	char* thumbprint = NULL;
	char* signAlg = NULL;

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
				//printf("%ws \n",tmpValue->CounterSign.TimeStamp);
				strDataCopy(&timesStamp, tmpValue->CounterSign.TimeStamp);
			}
		}

		GenericLL* certtmp = tmpValue->CertChain;
		GenericLL* tmpCert = NULL;
		int signCheck = 0;

		while (certtmp != NULL) {
			tmpCert = certtmp;
			tmpValue1 = (CERT_NODE_INFO*)certtmp->data;

			if (signCheck == 0) {
				strDataCopy(&publisher, tmpValue1->SubjectName);
				strDataCopy(&signAlg, tmpValue1->SignAlgorithm);
				strDataCopy(&thumbprint, strupr(tmpValue1->Thumbprint));
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


	if (thumbprint) {

		std::cout << thumbprint << std::endl;
		free(thumbprint);
	}
	if (publisher) {

		std::cout << publisher << std::endl;
		free(publisher);
	}
	if (signAlg) {

		std::cout << signAlg << std::endl;
		free(signAlg);
	}
	if (timesStamp) {

		std::cout << timesStamp << std::endl << std::endl;
		free(timesStamp);
	}

}

//__declspec(noinline) int getAllFilesFileParserW(WCHAR* rootDir, BOOL subDirectories, Tree* TrustedCAtree) {
//	BOOL bSubdirectory = FALSE;
//	HANDLE hFile = INVALID_HANDLE_VALUE;
//	WIN32_FIND_DATAW FileInformation;
//	size_t strPatternLen = wcslen(rootDir) + 6;
//	WCHAR* strPattern = (WCHAR*)calloc(strPatternLen, sizeof(WCHAR));
//
//	if (strPattern == NULL) {
//		wprintf(L"Memory allocation failed for strPattern\n");
//		return -1;
//	}
//
//	wcscpy_s(strPattern, strPatternLen, rootDir);
//	wcscat_s(strPattern, strPatternLen, L"\\*.*");
//
//	hFile = FindFirstFileW(strPattern, &FileInformation);
//	if (hFile == INVALID_HANDLE_VALUE) {
//		//wprintf(L"FindFirstFileW failed for pattern %s\n", strPattern);
//		free(strPattern);
//		return -1;
//	}
//
//	do {
//		if (FileInformation.cFileName[0] != '.') {
//			size_t strFilePathLen = wcslen(rootDir) + wcslen(FileInformation.cFileName) + 3;
//			WCHAR* strFilePath = (WCHAR*)calloc(strFilePathLen, sizeof(WCHAR));
//
//			if (strFilePath == NULL) {
//				wprintf(L"Memory allocation failed for strFilePath\n");
//				FindClose(hFile);
//				free(strPattern);
//				return -1;
//			}
//
//			wcscpy_s(strFilePath, strFilePathLen, rootDir);
//			wcscat_s(strFilePath, strFilePathLen, L"\\");
//			wcscat_s(strFilePath, strFilePathLen, FileInformation.cFileName);
//
//			if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
//				if (subDirectories) {
//					getAllFilesFileParserW(strFilePath, subDirectories, TrustedCAtree);
//				}
//				else {
//					bSubdirectory = TRUE;
//				}
//			}
//			else {
//				wprintf(L"filePath: %ls\n", strFilePath);
//				struct PEImgDetails* data = (struct PEImgDetails*)calloc(1, sizeof(PEImgDetails));
//				verifyCatlogFileAndGetData((wchar_t*)strFilePath, data, TrustedCAtree);
//				printf("Thumbprint:\t %s\n", data->thumbprint);
//				printf("Publisher:\t %s\n", data->publisher);
//				printf("TimeStamp:\t %s\n", data->timeStamp);
//				printf("signAlg:\t %s\n", data->signAlg);
//				printf("verified:\t %d\n", data->verified);
//
//				freeImgDetails(data);
//				if (data)
//					free(data);
//			}
//			free(strFilePath);
//		}
//	} while (FindNextFileW(hFile, &FileInformation) == TRUE);
//
//	FindClose(hFile);
//	free(strPattern);
//
//	return 0;
//}

// PEAnalyzer


__declspec(noinline)  int testSha256() {

	BCRYPT_ALG_HANDLE algHandle = NULL;
	NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"BCryptOpenAlgorithmProvider failed: 0x%x\n", ntStatus);
	}

	const wchar_t* filepath = L"c:\\windows\\notepad.exe";
	char hashValue[65] = { 0 };
	double totalTime = 0.0;
	int runs = 3; // Number of averaging runs

	for (int i = 0; i < runs; ++i) {
		clock_t begin = clock();

		for (int j = 0; j < 1000; ++j) {
			char hashValue[65] = { 0 };
			int status = FPSha256Calculation((wchar_t*)L"c:\\windows\\notepad.exe", hashValue);
			printf("%d %s\n", status, hashValue);

			/*char hashValue[65] = { 0 };
			int status = FPSha256CalculationWithHandle(algHandle, (wchar_t*)L"c:\\windows\\notepad.exe", hashValue);
			printf("%d %s\n", status, hashValue);*/
		}

		clock_t end = clock();
		double timeSpent = (double)(end - begin) / CLOCKS_PER_SEC;
		totalTime += timeSpent;

		printf("Run %d: Total Time for 100 executions: %.3f seconds\n", i + 1, timeSpent);
	}

	double averageTime = totalTime / runs;
	printf("\nAverage Time for 100 executions over %d runs: %.3f seconds\n", runs, averageTime);
	if (algHandle) BCryptCloseAlgorithmProvider(algHandle, 0);

	return 0;
}


int wmain(int argc, wchar_t** argv)
{

	//testSha256();

	int printDetails = 1;
	ScannerConfig malDetEngine = {0};
	wchar_t* baseDir = argv[2];
	wchar_t* winTrustedCertificatePath  =(wchar_t*) L"Resource\\WinTrustedCertificates";

	int initPEParserFlag = initPEParser((wchar_t*)L"d:\\yara.yar");
	std::wcout << initPEParserFlag << std::endl;
	//int initRuleEngineFlag = initRuleEngine(&malDetEngine, argv[1]);

	malDetEngine.mcScanFlag = 1;
	malDetEngine.yaraScanFlag = 1;


	HANDLE fileHandle = CreateFileW(
		baseDir,                    // File path
		GENERIC_READ,               // Open for reading
		FILE_SHARE_READ,            // Share for reading
		NULL,                       // Default security
		OPEN_EXISTING,              // Only open if file exists
		FILE_FLAG_SEQUENTIAL_SCAN,  // Optimization flag for sequential access
		NULL                        // No template file
	);

	clock_t begin = clock();

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
			std::cout << "Error creating file mapping" << std::endl;
			CloseHandle(fileHandle);
			return 1;
		}
		LPVOID mappedView = MapViewOfFile(
			mappingHandle,
			FILE_MAP_READ,
			0,
			0,
			0
		);
		if (mappedView == NULL) {
			std::cout << "Error mapping view of file" << std::endl;
			CloseHandle(mappingHandle);
			CloseHandle(fileHandle);
			return 1;
		}

		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)mappedView;
		if (23117 == (int)DosHeader->e_magic) {
			struct PEImgDetails* img = startPE(baseDir, &malDetEngine, mappedView); // 1 for yara scan on 
			//struct PEImgDetails* img = startPE(baseDir, root, TrustedCAtree, &mapMalwareFullFunc, fp, 2, img1);
			//std::cout << img->verified << std::endl;
			if (img != NULL) {
				printImgDetails(img, 1);
				freeImgDetails(img);
				if (img)
					free(img);
			}
			else {
				printf("img is null");
			}
		}
		else {
			printf("Warning: InvalidExe\n");
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
	else
	{
		// while (1) {
		
		getAllFilesFileParserW(baseDir,  1, &malDetEngine, printDetails); // 1 for yara scan on 
		// }
	}



	clock_t end = clock();
	double time_spent = (double)((double)end - (double)begin);
	time_spent = time_spent / CLOCKS_PER_SEC;
	printf("Info: OverAll Time Taken is %lf \n\n\n", time_spent);
	return 1;
}

