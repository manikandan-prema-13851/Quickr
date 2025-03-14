
#include "PatternScanner.h"
#include "Header.h"
#include "fUtil.h"

struct RULE_ENGINE* patternRules = NULL;
int32_t patternRuleInitFlag = false;

const wchar_t* getFileExternsionW(const wchar_t* filename) {
	const wchar_t* dot = wcsrchr(filename, L'.');
	if (!dot || dot == filename) return L"";
	return dot + 1;
}

int internal_callback_function(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
	CallbackData* callback_data = (CallbackData*)user_data;
	if (message == CALLBACK_MSG_RULE_MATCHING) {
	
		YR_RULE* rule = (YR_RULE*)message_data;

		YR_STRING* string;
		YR_MATCH* match;

		// Iterate over strings and matches in the rule
		yr_rule_strings_foreach(rule, string) {
			yr_string_matches_foreach(context, string, match) {
				// Extract the name and offset
				char* malware_name = (char*)rule->identifier;
				size_t offset = match->base + match->offset;
				//printf("classifier nname : %s\n", malware_name);
				PatternScanResultData data = { malware_name, offset };

				// Call the user's callback function with the extracted data
				callback_data->user_callback(context, message, &data, callback_data->user_data);

				// Stop the scan after the first match
				return CALLBACK_ABORT;
			}
		}
	}
	return CALLBACK_CONTINUE;
}

int user_callback_function(void* context, int message, void* message_data, void* user_data) {
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		PatternScanResultData* data = (PatternScanResultData*)message_data;

		struct PEImgDetails* fmeta = (struct PEImgDetails*)user_data;
		strDataCopy(&fmeta->mcAnalysis.patternString, data->name);
		fmeta->mcAnalysis.patternOffset = data->offset;
		fmeta->mcAnalysis.isYaraMalware = MC_MALWARE;
		//printf("Detected : %s,%s,%zu\n", fmeta->filePath, data->name, data->offset);
	}
	return CALLBACK_CONTINUE;
}

void unInitRuleEngine(struct RULE_ENGINE* patternRules) {
	if (patternRules) {
		yr_rules_destroy((YR_RULES*)patternRules);
	}
	yr_finalize();
}

__declspec(noinline) int scanRuleEngine(struct PEImgDetails* data, LPVOID fp) {
	if (patternRuleInitFlag == true && patternRules != NULL) {

		if(data->verified != 1){
			CallbackData callback_data = { user_callback_function, data };
			int result = yr_rules_scan_mem((YR_RULES*)patternRules, fp, data->fileSize, 0, internal_callback_function, &callback_data, 0);
			if (result != ERROR_SUCCESS) {
				printf("Error scanning memory: %d\n", result);
			}
			else {
				//printf("Scan completed successfully.\n");
			}
		}
	}
	else {
		//printf("[FAILURE] malDetEngine Uninit.\n");
	}

	if (data->mcAnalysis.isYaraMalware != MC_MALWARE) {
		data->mcAnalysis.isYaraMalware = MC_BENIGN;
		data->mcAnalysis.patternString = NULL;
		data->mcAnalysis.patternOffset = 0;
	}
	return EXIT_SUCCESS;
}

// init pattern engine if success return 0 else return 1
__declspec(noinline) int initRuleEngineInternal(const wchar_t* compiled_rules_file) {
	patternRuleInitFlag = false;
	if (patternRules != NULL) {
		unInitRuleEngine(patternRules);
	}
	patternRules = NULL;
	if (yr_initialize() != ERROR_SUCCESS) {
		printf("Failed to initialize the Engine\n");
		return EXIT_FAILURE;
	}
	const wchar_t* rules_ext = getFileExternsionW(compiled_rules_file);
	patternRules = (struct RULE_ENGINE*)calloc(1, sizeof(RULE_ENGINE));
	if (wcscmp(rules_ext, L"yc") == 0 || wcscmp(rules_ext, L"yarac") == 0) { // Load compiled rules
		YR_STREAM stream;
		FILE* fp = _wfopen(compiled_rules_file, L"rb");
		if (fp == NULL) {
			wprintf(L"Failed to open rule file: %s \n", compiled_rules_file);
			return EXIT_FAILURE;
		}
		stream.user_data = fp;
		stream.read = (YR_STREAM_READ_FUNC)fread;

		if (yr_rules_load_stream(&stream, (YR_RULES**)&patternRules) != ERROR_SUCCESS) {
			printf("Failed to load compiled rules from file\n");
			yr_finalize();
			if (fp != NULL) {
				fclose(fp);
			}
			return EXIT_FAILURE;
		}

		if (fp != NULL)
			fclose(fp);

	}

	else if (wcscmp(rules_ext, L"yar") == 0) {  // Compile and load regular rules

		YR_COMPILER* compiler = NULL;

		if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
			printf("Failed to create YARA compiler\n");
			yr_finalize();
			return EXIT_FAILURE;
		}
		FILE* fp = _wfopen(compiled_rules_file, L"rb");
		if (fp == NULL) {
			wprintf(L"Failed to open rule file: %s \n", compiled_rules_file);
			yr_compiler_destroy(compiler);
			yr_finalize();
			return EXIT_FAILURE;
		}

		if (yr_compiler_add_file(compiler, fp, NULL, (const char*)compiled_rules_file) != ERROR_SUCCESS) {
			wprintf(L"Failed to compile rule file: %s\n", compiled_rules_file);
			fclose(fp);
			yr_compiler_destroy(compiler);
			yr_finalize();
			return EXIT_FAILURE;
		}

		if (fp != NULL) {
			fclose(fp);
		}


		if (yr_compiler_get_rules(compiler, (YR_RULES**)&patternRules) != ERROR_SUCCESS) {
			fprintf(stderr, "Failed to get compiled rules\n");
			yr_compiler_destroy(compiler);
			yr_finalize();
			return EXIT_FAILURE;
		}
		yr_compiler_destroy(compiler);
	}
	else {
		wprintf(L"Unsupported rule file extension: %ls\n", rules_ext);
		yr_finalize();
		return EXIT_FAILURE;
	}
	
	patternRuleInitFlag = true;
	return EXIT_SUCCESS;
}
