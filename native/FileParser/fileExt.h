#ifndef FILEEXT_H
#define FILEEXT_H

#include<stdio.h>
#include <Windows.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>

#define MAXLEN (256)
#pragma warning (disable:4996)
#define ARRAY_SIZE(a) sizeof(a)/sizeof(a[0])
#define TOTALMIMETYPE 390

struct MimeValue {
	char* exttype;
	char* mimetype;
	struct MimeValue* next;
};

struct ExtNode {
	UINT8 key;
	struct ExtNode* left;
	struct ExtNode* right;
	struct ExtNode* nextLevel;
	struct MimeValue* MimeValue;
};

struct signatureKey {
	UINT8* arr;
	int size;
};

struct signatureMap {
	struct signatureKey key;
	struct MimeValue value;
};

struct FileInfoData {
	char CompanyName[256];
	char FileDescription[256];
	char FileVersion[256];
	char InternalName[256];
	char LegalCopyright[256];
	char OriginalFilename[256];
	char ProductName[256];
	char ProductVersion[256];
	char VarFileInfo[256];

	// for catlog or embeded type information 
	char ThumbPrint[256];
	char SignType[256];
	char SignAlg[256];
	char Publisher[256];
	char Status[256];

};

__declspec(noinline) struct ExtNode* createNodeTrie(UINT8, struct MimeValue*);
__declspec(noinline) void initTriavllist(struct ExtNode*);
__declspec(noinline) struct MimeValue* searchTrie(struct ExtNode* root, UINT8* cbbyte, size_t bufsize1);
__declspec(noinline) struct MimeValue* searchNodeTrie(struct ExtNode* root, UINT8* sear, size_t searLen);
__declspec(noinline) void print_node(struct ExtNode* root, int space, int result);

#endif // !FILEEXT_H
