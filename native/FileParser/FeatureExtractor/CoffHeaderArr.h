#include "FeatureHeader.h"
#include<Windows.h>

__declspec(noinline) void machineHashData(struct FeatNode** head, WORD hex);
__declspec(noinline) void charHashData(struct FeatNode** head, WORD hex);
__declspec(noinline) void sectionCharData(struct FeatNode** head, DWORD switchcasevalue, int*, int*, int*, int);