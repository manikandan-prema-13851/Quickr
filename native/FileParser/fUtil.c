#include "fUtil.h"
#include "asn1.h"
#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

int enterTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef) {
	int ret = mbedtls_asn1_get_tag(buffer, end, lSize, tagKey);
	//DEBUG//printf("%f.  Returned %x ->  Buffer %p  Len %d  and End %p\n", dbgRef, ret < 0 ? -(unsigned)ret : ret, * buffer, * lSize, end);
	//printAsHex(*buffer, ((*lSize > 10) ? 10 : *lSize));
	//printf("\n");
	return ret;
}


int skipTLV(char** buffer, char* end, size_t* lSize, int tagKey, float dbgRef) {
	int ret = mbedtls_asn1_get_tag(buffer, end, lSize, tagKey);
	//DEBUG//printf("%f.  Returned %x ->  Buffer %p  Len %d  and End %p\n", dbgRef, ret < 0 ? -(unsigned)ret : ret, *buffer, *lSize, end);
	//printAsHex(*buffer, ((*lSize > 10) ? 10 : *lSize));
	//printf("\n\n");
	if (ret >= 0)*buffer = *buffer + *lSize;
	return ret;
}


void strDataNCopy(char** destination, const char* source, size_t strLenSource) {
	if (!source || strLenSource == 0) {
		*destination = NULL;
		return;
	}

	*destination = (char*)calloc(strLenSource + 1, sizeof(char)); 
	if (*destination) {
		memcpy(*destination, source, strLenSource);
		(*destination)[strLenSource] = '\0'; 
	}
}


void strDataCopy(char** destination, const char* source) {
	if (!source) {
		*destination = NULL;
		return;
	}

	size_t strLenSource = strlen(source);
	strDataNCopy(destination, source, strLenSource);
}



int is_string_not_empty(const char* str) {
	return str != NULL && strlen(str) > 0;
}
int is_wstring_not_empty(const wchar_t* str) {
	return str != NULL && wcslen(str) > 0;
}

void wstrDataNCopy(wchar_t** destination, const wchar_t* source, size_t strLenSource) {
	if (!source || strLenSource == 0) {
		*destination = NULL;
		return;
	}

	*destination = (wchar_t*)calloc(strLenSource + 1, sizeof(wchar_t));
	if (*destination) {
		wmemcpy(*destination, source, strLenSource);
		(*destination)[strLenSource] = L'\0';  // Ensure null termination
	}
}

void wstrDataCopy(wchar_t** destination, const wchar_t* source) {
	if (!source) {
		*destination = NULL;
		return;
	}

	size_t strLenSource = wcslen(source);
	wstrDataNCopy(destination, source, strLenSource);
}


//void wstrToStr(char** destination, const wchar_t* source) {
//	int strLenSource = WideCharToMultiByte(CP_UTF8, 0, source, -1, NULL, 0, NULL, NULL);
//	if (strLenSource == 0) {
//		printf("WideCharToMultiByte failed to calculate the required buffer size.\n");
//		return;
//	}
//	*destination = (char*)calloc(strLenSource, sizeof(char));
//	if (*destination == NULL) {
//		printf("Failed to allocate memory for the multi-byte string.\n");
//		return;
//	}
//	int result = WideCharToMultiByte(CP_UTF8, 0, source, -1, *destination, strLenSource, NULL, NULL);
//	if (result == 0) {
//		printf("WideCharToMultiByte failed to convert the string.\n");
//		free(*destination);
//		*destination = NULL;
//	}
//}

char* wStringToString(wchar_t* src)
{
	int  CodePage = CP_UTF8;

	int length = WideCharToMultiByte(CodePage, 0, src, -1, NULL, 0, NULL, NULL);
	char result[2000];
	if (0 != WideCharToMultiByte(CodePage, 0, src, -1, result, length, NULL, NULL)) {
		return result;
	}
	return NULL;
}



void strToWstr(wchar_t** destination, const char* source) {
	int strLenSource = MultiByteToWideChar(CP_UTF8, 0, source, -1, NULL, 0);
	if (strLenSource == 0) {
		printf("MultiByteToWideChar failed to calculate the required buffer size.\n");
		return;
	}
	*destination = (wchar_t*)calloc(strLenSource, sizeof(wchar_t));
	if (*destination == NULL) {
		printf("Failed to allocate memory for the wide-character string.\n");
		return;
	}
	int result = MultiByteToWideChar(CP_UTF8, 0, source, -1, *destination, strLenSource);
	if (result == 0) {
		printf("MultiByteToWideChar failed to convert the string.\n");
		free(*destination);
		*destination = NULL;
	}
}

void wstrDataToStrCopy(char** destination, wchar_t* source) {
	char* sourceStr = wStringToString(source);
	if (sourceStr) {
		size_t strLenSource = strlen(sourceStr) + 1;
		strDataNCopy(destination, sourceStr, strLenSource);
	}
	if (sourceStr) {
		free(sourceStr);
	}
}
