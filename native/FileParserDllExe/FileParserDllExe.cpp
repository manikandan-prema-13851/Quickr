#include <iostream>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

extern "C"
{
#include "FileParser.h"
#include "../FeatureExtractor/FeatureHeader.h"
}

int fileCount = 0;

typedef int (*initPEParserDLL)(MalwareDetectionEngine* , wchar_t*);
typedef struct PEImgDetails* (*startPEDLL)(wchar_t*, MalwareDetectionEngine* malDetEngine);
typedef int (*printImgDetailsDLL)(struct PEImgDetails*, int);
typedef void (*freeImgDetailsDLL)(struct PEImgDetails*);
typedef int (*getAllFilesFileParserDLL)(const wchar_t*, BOOL,MalwareDetectionEngine*, int);
typedef int  (*freePEParserStructDLL)(Tree_t**, struct ExtNode**, struct hashTableMalwareFullFunc*);
typedef int (*initRuleEngineDLL)(MalwareDetectionEngine*, wchar_t*);
HINSTANCE hinstMC = NULL;
initPEParserDLL initPEParserDLLApi;
startPEDLL startPEDLLApi;
printImgDetailsDLL printImgDetailsDLLApi;
freeImgDetailsDLL freeImgDetailsDLLApi;
getAllFilesFileParserDLL getAllFilesFileParserDLLApi;
freePEParserStructDLL freePEParserStructDLLApi;
initRuleEngineDLL initRuleEngineDLLApi;

int FileParserLoad(std::wstring filePath) {
	try {

		hinstMC = LoadLibrary(filePath.c_str());
		if (hinstMC == NULL) {
			std::cout << "Dll Load Failed " << std::endl;
			return -1;
		}
		initPEParserDLLApi = (initPEParserDLL)GetProcAddress(hinstMC, "initPEParserDWrapper");
		initRuleEngineDLLApi = (initRuleEngineDLL)GetProcAddress(hinstMC, "initRuleEngineDLLWrapper");
		startPEDLLApi = (startPEDLL)GetProcAddress(hinstMC, "startPEDWrapper");
		printImgDetailsDLLApi = (printImgDetailsDLL)GetProcAddress(hinstMC, "printImgDetailsDWrapper");
		freeImgDetailsDLLApi = (freeImgDetailsDLL)GetProcAddress(hinstMC, "freeImgDetailsDWrapper");
		getAllFilesFileParserDLLApi = (getAllFilesFileParserDLL)GetProcAddress(hinstMC, "getAllFilesFileParserDWrapperW");
		freePEParserStructDLLApi = (freePEParserStructDLL)GetProcAddress(hinstMC, "freePEParserStructDWrapper");
		if (initPEParserDLLApi == NULL) {
			std::cout << "Dll Load Failed  initPEParserDLLApi" << std::endl;
		}
		if (initRuleEngineDLLApi == NULL) {
			std::cout << "Dll Load Failed  initRuleEngineDLLApi" << std::endl;
		}
		if (startPEDLLApi == NULL) {
			std::cout << "Dll Load Failed  startPEDLLApi" << std::endl;
		}
		if (printImgDetailsDLLApi == NULL) {
			std::cout << "Dll Load Failed  printImgDetailsDLLApi" << std::endl;
		}
		if (freeImgDetailsDLLApi == NULL) {
			std::cout << "Dll Load Failed  freeImgDetailsDLLApi" << std::endl;
		}
		if (getAllFilesFileParserDLLApi == NULL) {
			std::cout << "Dll Load Failed  getAllFilesFileParserDLLApi" << std::endl;
		}
		if (freePEParserStructDLLApi == NULL) {
			std::cout << "Dll Load Failed  freePEParserStructDLLApi" << std::endl;
		}
		return 1;
	}
	catch (const std::exception& ex) {
		std::cout << "Error : ";
		std::cout << ex.what() << std::endl;
		return -1;
	}
}

int wmain(int argc, wchar_t** argv)
{
	wchar_t* baseDir = argv[2];
	//system("PAUSE");
	//int printDetails = atoi(argv[2]);
	int printDetails = 1;
	MalwareDetectionEngine malDetEngine = { 0 };
	FileParserLoad(L"FileParserDll.dll");

	clock_t begin;

	//int initPEParserFlag = initPEParser(&TrustedCAtree, &root, &mapMalwareFullFunc);
	wchar_t* winTrustedCertificatePath = (wchar_t*)L"Resource\\WinTrustedCertificates";
	int initPEParserFlag = initPEParserDLLApi(&malDetEngine, winTrustedCertificatePath);
	int initRuleEngineFlag = initRuleEngineDLLApi(&malDetEngine, argv[1]);

	malDetEngine.mcScanFlag = 1;
	malDetEngine.yaraScanFlag = 1;

	if (initPEParserFlag == 1) {
		printf("Warning: Something Get Wrong InitFailed\n");
		return EXIT_FAILURE;
	}
	if (initRuleEngineFlag == 1) {
		printf("Warning: Something Get Wrong InitFailed\n");
		return EXIT_FAILURE;
	}
	HANDLE fileHandle = CreateFileW(
		baseDir,                    // File path
		GENERIC_READ,               // Open for reading
		FILE_SHARE_READ,            // Share for reading
		NULL,                       // Default security
		OPEN_EXISTING,              // Only open if file exists
		FILE_FLAG_SEQUENTIAL_SCAN,  // Optimization flag for sequential access
		NULL                        // No template file
	);


	begin = clock();

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
			while(1){
			//struct PEImgDetails* img = startPE(baseDir, root, TrustedCAtree, &mapMalwareFullFunc, fp);
			struct PEImgDetails* img = startPEDLLApi(baseDir, &malDetEngine);
			//struct PEImgDetails* img = startPEDLLApi(baseDir, root, TrustedCAtree, &mapMalwareFullFunc, mappedView, 2, img1);
			if (img != NULL) {
				//printImgDetails(img, printDetails);
				printImgDetailsDLLApi(img, printDetails);
				//freeImgDetails(img);
				freeImgDetailsDLLApi(img);
				if (img)
					free(img);
			}
			else {

			}
			}
		}
		else {
			printf("Warning: InvalidExe\n");
		}
	}
	else
	{
		//getAllFilesFileParser(baseDir, root, 1, TrustedCAtree, &mapMalwareFullFunc, printDetails);
		getAllFilesFileParserDLLApi(baseDir, 1, &malDetEngine, printDetails);
	}

	//freePEParserStructDLLApi(&TrustedCAtree, &root, &mapMalwareFullFunc);

	clock_t end = clock();
	double time_spent = (double)((double)end - (double)begin);
	time_spent = time_spent / CLOCKS_PER_SEC;
	printf("Info: OverAll Time Taken is %lf \n\n\n", time_spent);
	return 1;
}