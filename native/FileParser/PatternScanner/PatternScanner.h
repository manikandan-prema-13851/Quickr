#ifndef PATTERNSCANNER_H
#define PATTERNSCANNER_H
#include <yara/filemap.h>
#include <yara/libyara.h>
#include <yara/stream.h>
#include <yara/types.h>
#include <yara/rules.h>
#include <yara/compiler.h>

typedef struct YR_RULES RULE_ENGINE;

typedef struct {
	YR_CALLBACK_FUNC user_callback;
	void* user_data;
} CallbackData;

typedef struct {
	char* name;
	size_t offset;
} PatternScanResultData;

__declspec(noinline) int initRuleEngineInternal(const wchar_t* compiled_rules_file);
__declspec(noinline) int scanRuleEngine(struct PEImgDetails* data, LPVOID fp);
#endif

// Compare this snippet from FileParser/PatternScanner/PatternScanner.c:
