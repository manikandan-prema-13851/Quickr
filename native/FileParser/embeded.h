
#ifndef EMBEDDED_H
#define EMBEDDED_H
#include "pe.h"
#include "FileParser.h"

__declspec(noinline) int pefile_strip_sig_wrapper(FILE* fp, struct pefile_context* ctx, struct PEImgDetails* data);
__declspec(noinline) int isZohoBinary(FILE* fp, char* buffer, size_t lSize, struct pefile_context* ctx, struct PEImgDetails* peSignInfo, Tree_t* TrustedCAtree, struct PEImgDetails* data);
void convertFilePath(char* originalPath, char* convertedPath);
__declspec(noinline) int extractRawSignedData(const char* p, size_t len, struct ExtractedSignedData* esd);
__declspec(noinline) int parseSignerInfo(struct ExtractedSignedData* esd, struct ParsedSignerInfo* psignInfo);
__declspec(noinline) int verifyCertficateData(struct ExtractedSignedData* esd, struct ParsedSignedData* psd, Tree_t* TrustedCAtree);
#endif EMBEDDED_H