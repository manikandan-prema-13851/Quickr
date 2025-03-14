#include "TestUtils.h"
#if CREATE_NEW_CATCHFILE
#include "pch.h"
#include "CppUnitTest.h"
#include "FileParserUtils.cpp"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;
FileParserUtils* FileParserUtils::instance = nullptr;
#include "GenericLogger.h"

namespace CreateCatch
{
	TEST_CLASS(CreateCatch)
	{
	public:
		TEST_METHOD(ExecuteAllTestsSequentially) {
			NotePad();
			ScanOneFile();
			Git();
			FolderScan();
		}

	private:
		void NotePad() {
			FileParserUtils* parserUtils = FileParserUtils::getInstance();
			std::wstring baseDir = L"D:\\gitrepo\\fileparser\\Master_VS22_NO_LTCG\\fileparser\\native\\FileParser\\";
			parserUtils->initPEParserWrapper(baseDir);

			int yaraEngineFlag = 0;
			if (yaraEngineFlag == 1) {

			}
			else {
				TestUtils::print(L"YaraEngine Not Enable For Testing");
			}

			std::wstring basedir = parserUtils->baseDirPath + L"Resource\\dataset\\benign\\Notepad";
			ImgDetails imgdata;
			parserUtils->featureExtractAndPutAVL(basedir, &imgdata);
		}

		void Git() {
			FileParserUtils* parserUtils = FileParserUtils::getInstance();
			std::wstring basedir = parserUtils->baseDirPath + L"Resource\\dataset\\benign\\Git";
			ImgDetails imgdata;
			parserUtils->featureExtractAndPutAVL(basedir, &imgdata);
		}

		void ScanOneFile() {
			FileParserUtils* parserUtils = FileParserUtils::getInstance();
			std::wstring basedir = parserUtils->baseDirPath + L"Resource\\dataset\\benign\\exe_only\\may12-signed\\0A94E463AD77504F8C80BB21A53B70E34731A7D15949A3420D9E2579C5F6E5A2";
			ImgDetails imgdata;
			parserUtils->featureExtractAndPutAVL(basedir, &imgdata);
		}

		void FolderScan() {
			FileParserUtils* parserUtils = FileParserUtils::getInstance();
			std::wstring basedir = parserUtils->baseDirPath + L"Resource\\dataset\\benign";
			ImgDetails imgdata;
			parserUtils->featureExtractAndPutAVL(basedir, &imgdata);
		}
	};
}

#endif // CREATE_NEW_CATCHFILE
