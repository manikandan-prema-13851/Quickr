#include "PEScanner.h"
#include <windows.h>
#include "chrono"

namespace quickrengine {
	PEScanner* PEScanner::instance = 0;


	bool PEScanner::isReadyState() {
		return ready;
	}

	bool PEScanner::initPEScanner(wchar_t* yaraRulePath) {
		ready = false;
		int retStatus = initPEParser(yaraRulePath); // EXIT_SUCCESS for init done else EXIT_FAILURE
		if (retStatus == EXIT_SUCCESS) {
			ready = true;
		}
		else {
			ready = false;
			std::wcout << L"PEScanner Service Not Available" << std::endl;
		}
		return ready;
	}

	void PEScanner::printPEData(struct PEImgDetails* peData, ScannerConfig* scanConfig) {
		printImgDetails(peData, scanConfig->printPEData);
	}

	void PEScanner::freePEData(struct PEImgDetails* peData) {
		freeImgDetails(peData);
	}

	struct PEImgDetails* PEScanner::PEScanFile(wchar_t* baseDir, ScannerConfig* scanConfig) {
		return PEFileScanner(baseDir, scanConfig);
	}


}