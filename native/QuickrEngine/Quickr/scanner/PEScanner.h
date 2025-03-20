#ifndef QUICKR_PESCANNER_H
#define QUICKR_PESCANNER_H

#include <iostream>
extern "C"
{
    #include "FileParser.h"
    #include "FeatureExtractor/FeatureHeader.h"
}

#include "../QuickrEngine/quickengine_version.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

namespace quickrengine {

    class PEScanner {
    public:
        PEScanner(const PEScanner&) = delete;
        PEScanner& operator=(const PEScanner&) = delete;

        static PEScanner* getInstance() {
            if (instance == nullptr) {
                instance = new PEScanner(); // create instance
            }
            return instance;
        }

        bool initPEScanner(wchar_t* yaraRulePath); //  reinit when it needs it can delete the old instance
        bool isReadyState();
        struct PEImgDetails* PEScanFile(wchar_t* baseDir, ScannerConfig* scanConfig);
        void printPEData(struct PEImgDetails* peData, ScannerConfig* scanConfig);
        void freePEData(struct PEImgDetails* peData);

    private:
        static PEScanner* instance;
        std::atomic<bool> ready = false;
        PEScanner() = default;
    };

}
#endif