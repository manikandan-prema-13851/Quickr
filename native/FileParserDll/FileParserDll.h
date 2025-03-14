#ifndef FILEPARSER_DLL

#define FILEPARSER_DLL

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

#include <stdio.h>

#include "FileParser.h"
#include "FeatureExtractor/FeatureHeader.h"

// Fileparser Function Wrapper For DLL
__declspec(dllexport)int  initPEParserDWrapper(MalwareDetectionEngine* malDetEngine, wchar_t*);

__declspec(dllexport) struct PEImgDetails* startPEDWrapper(wchar_t*, MalwareDetectionEngine* malDetEngine);

__declspec(dllexport) void printImgDetailsDWrapper(struct PEImgDetails*, int);

__declspec(dllexport) void freeImgDetailsDWrapper(struct PEImgDetails*);

__declspec(dllexport) int getAllFilesFileParserDWrapperW(wchar_t* rootDir, BOOL subDirectories, MalwareDetectionEngine* malDetEngine, int printDetails);

__declspec(dllexport) int freePEParserStructDWrapper(Tree_t**, struct ExtNode**, struct hashTableMalwareFullFunc*);

__declspec(dllexport) int FPSha256CalculationWrapper(const wchar_t* filepath, char* hashValue);

#endif
