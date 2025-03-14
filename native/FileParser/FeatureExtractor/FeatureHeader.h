#ifndef FEATUREHEADER_H
#define FEATUREHEADER_H
#include <time.h>
#include<stdio.h>
#include<Windows.h>
//#include<winnt.h>
#include <math.h>
#include<stdint.h>
#include<string.h>
#include "DataAlign_Hash.h"
#include "CoffHeaderArr.h"
#include "OptionalHeader.h"
#include "cMalwareDetails.h"
#include "Header.h"
#pragma warning(disable:4146)
#pragma warning (disable: 4996)
#define maxA(a,b) (((a) > (b)) ? (a) : (b))
#pragma warning(disable:6031)
typedef unsigned long long QWORD;
#define log2of10 3.32192809488736234787


__declspec(noinline) struct FeatNode* collectMC(FILE* fp, struct PEImgDetails* fullFeatureArr,int* isexe);

struct FeatNode {
	float value;
	char* key;
	struct FeatNode* next;
};


__declspec(noinline) void freeFeatNode(struct FeatNode* headNode);
__declspec(noinline) void featNodeAppend(struct FeatNode** head_ref, char* key, float value);
__declspec(noinline) void printList(struct FeatNode* node);

struct FeatNode* createFeatNode();

__declspec(noinline) void searchInsertFeatNode(struct FeatNode** head_ref, char* key, float value);
__declspec(noinline) void searchInsertFeatNodeN(struct FeatNode** head_ref, char* key, float value);
__declspec(noinline) int findlength(struct FeatNode* head);

/* MALWARE IMPORT FUNCTION START */

#define MALWAREFULLFUNCSIZE 256

struct entryMalwareFullFunc {
	char* key;
	int value;
	struct entryMalwareFullFunc* next;
};

struct hashTableMalwareFullFunc {
	struct entryMalwareFullFunc* valueEntry[MALWAREFULLFUNCSIZE];
};
struct ImpFunctionMap {
	char* key;
	int value;
};
__declspec(noinline) void InitMalwareFullFunc(struct hashTableMalwareFullFunc* mapMalwareFullFunc);
__declspec(noinline)  int retrieveMalwareFullFunc(struct hashTableMalwareFullFunc* ht, char* key);
/* MALWARE IMPORT FUNCTION END */

#endif
