// FileParserDll.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "FileParserDll.h"



__declspec(dllexport)int  initPEParserDWrapper(MalwareDetectionEngine* malDetEngine, wchar_t* winTrustedCertificatePath) {
    return initPEParser(malDetEngine);
}

__declspec(dllexport)int  initRuleEngineDLLWrapper(MalwareDetectionEngine* malDetEngine, wchar_t* ruleFile) {
    return initRuleEngine(malDetEngine);
}
__declspec(dllexport) struct PEImgDetails* startPEDWrapper(wchar_t* filePath, MalwareDetectionEngine* malDetEngine) {
    HANDLE fileHandle = CreateFile(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (fileHandle != INVALID_HANDLE_VALUE) {


        // Create a file mapping object
        HANDLE mappingHandle = CreateFileMapping(
            fileHandle,
            NULL,
            PAGE_READONLY,
            0,
            0,
            NULL
        );

        if (mappingHandle == NULL) {
            printf("Error creating file mapping");
            CloseHandle(fileHandle);
            return NULL;
        }

        // Map the file into memory
        LPVOID mappedView = MapViewOfFile(
            mappingHandle,
            FILE_MAP_READ,
            0,
            0,
            0
        );

        if (mappedView == NULL) {
            printf("Error mapping view of file");
            CloseHandle(mappingHandle);
            CloseHandle(fileHandle);
            return NULL;
        }

        // Call startPE with the mapped memory instead of a FILE* pointer
        struct PEImgDetails* data = startPE(filePath, malDetEngine, mappedView);

        // Clean up the mapping and file handle after calling startPE
        UnmapViewOfFile(mappedView);
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        return data;
    }
    printf("Create File Failed");
    return NULL;
}

__declspec(dllexport) void printImgDetailsDWrapper(struct PEImgDetails* data, int printDetails) {
	printImgDetails(data, printDetails);
}


__declspec(dllexport) void freeImgDetailsDWrapper(struct PEImgDetails* data) {
	freeImgDetails(data);
}

__declspec(dllexport) int getAllFilesFileParserDWrapperW(wchar_t* rootDir, BOOL subDirectories, MalwareDetectionEngine* malDetEngine, int printDetails) {
	return getAllFilesFileParserW(rootDir, subDirectories, malDetEngine, printDetails);
}


__declspec(dllexport) int getAllFilesFileParserDWrapper(const char* rootDir, BOOL subDirectories, MalwareDetectionEngine* malDetEngine, int printDetails) {
	return getAllFilesFileParser(rootDir, subDirectories, malDetEngine, printDetails);
}

__declspec(dllexport) int freePEParserStructDWrapper(Tree_t** TrustedCAtree, struct ExtNode** root, struct hashTableMalwareFullFunc* mapMalwareFullFunc) {
	return freePEParserStruct(TrustedCAtree, root, mapMalwareFullFunc);
}

__declspec(dllexport) int FPSha256CalculationWrapper(const wchar_t* filepath, char* hashValue) {
	return FPSha256Calculation(filepath, hashValue);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
