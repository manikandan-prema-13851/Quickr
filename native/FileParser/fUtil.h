#ifndef FUTIL_H
#define FUTIL_H
#include "Header.h"
int enterTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef);
int skipTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef);
void strDataNCopy(char** destination, char* source, size_t strLenSource);
void strDataCopy(char** destination, char* source);
int is_string_not_empty(const char* str);
int is_wstring_not_empty(const wchar_t* str);
void wstrDataCopy(wchar_t** destination, const wchar_t* source);
void wstrDataNCopy(wchar_t** destination, const wchar_t* source, size_t strLenSource);
void wstrDataToStrCopy(char** destination, wchar_t* source);
void strToWstr(wchar_t** destination, const char* source);
char* wStringToString(wchar_t* src);
#endif // !FUTIL_H
