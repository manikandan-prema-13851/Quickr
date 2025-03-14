#pragma once
#include <string>
#include <iostream>
#include "CppUnitTest.h"
#include "TestUtils.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

extern "C"
{
#include "FileParser.h"
#include "FeatureExtractor/FeatureHeader.h"

}
using namespace Microsoft::VisualStudio::CppUnitTestFramework;
#include "GenericLogger.h"

class FileParserUtils {
private:
	FileParserUtils() {}
	~FileParserUtils() = default;
	// prevent fileparserutils 
	FileParserUtils(const FileParserUtils&) = delete;
	FileParserUtils& operator=(const FileParserUtils&) = delete;

	static FileParserUtils* instance;
	MalwareDetectionEngine malDetEngine = { 0 };


public:
	MMapAVLLib* catchUpForFP = NULL;
	bool catchUpForFPFlag = false;
	int initPEParserFlag = 0, initRuleEngineFlag = 0;
	std::wstring baseDirPath;
	static FileParserUtils* getInstance() {
		if (instance == nullptr) {
			TestUtils::print(L"FileParser Instance Created");
			instance = new FileParserUtils();
		}
		return instance;
	}

	void initPEParserWrapper(std::wstring basepath) {
		baseDirPath = basepath;
		initPEParserFlag = initPEParser((wchar_t*)L"d:\\yara.yar");
		Assert::AreEqual(initPEParserFlag, 0, L"Init MalDetEngine failed");
		std::wstring baseDir = baseDirPath + L"Resource\\CatchData\\";
		catchUpForFP = initCatchUp(baseDir);
	}

	static int printImgDetailsWrapper(PEImgDetails* img, int printLog) {
		printImgDetails(img, printLog);
		return EXIT_SUCCESS;
	}

	static int freeImgDetailsWrapper(PEImgDetails*  img) {
		freeImgDetails(img);
		if (img) {
			free(img);
			img = NULL;
		}
		return EXIT_SUCCESS;
	}

	PEImgDetails* startPEWrapper(std::wstring filePath) {
		HANDLE fileHandle = CreateFileW(
			filePath.c_str(),           // File path
			GENERIC_READ,               // Open for reading
			FILE_SHARE_READ,            // Share for reading
			NULL,                       // Default security
			OPEN_EXISTING,              // Only open if file exists
			FILE_FLAG_SEQUENTIAL_SCAN,  // Optimization flag for sequential access
			NULL                        // No template file
		);

		clock_t begin = clock();

		if (fileHandle != INVALID_HANDLE_VALUE)
		{

			HANDLE mappingHandle = CreateFileMapping(
				fileHandle,
				NULL,
				PAGE_READONLY,
				0,
				0,
				NULL
			);
			if (mappingHandle == NULL) {
				Logger::WriteMessage((filePath + L" Error creating file mapping").c_str());
				CloseHandle(fileHandle);
				return NULL;
			}
			LPVOID mappedView = MapViewOfFile(
				mappingHandle,
				FILE_MAP_READ,
				0,
				0,
				0
			);
			if (mappedView == NULL) {
				std::cout << "Error mapping view of file" << std::endl;
				CloseHandle(mappingHandle);
				CloseHandle(fileHandle);
				return NULL;
			}

			IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)mappedView;
			struct PEImgDetails* img = NULL;
			if (23117 == (int)DosHeader->e_magic) {
				malDetEngine.mcScanFlag = 1;
				malDetEngine.yaraScanFlag = 1;
				img = startPE((wchar_t*)filePath.c_str(), &malDetEngine, mappedView);
				//struct PEImgDetails* img = startPE(baseDir, root, TrustedCAtree, &mapMalwareFullFunc, fp, 2, img1);
				//std::cout << img->verified << std::endl;
				
			}
			else {
				printf("Warning: InvalidExe\n");
			}


			if (mappedView != NULL) {
				UnmapViewOfFile(mappedView);
				mappedView = NULL;
			}

			if (mappingHandle != NULL && mappingHandle != INVALID_HANDLE_VALUE) {
				CloseHandle(mappingHandle);
				mappingHandle = NULL;
			}

			if (fileHandle != NULL && fileHandle != INVALID_HANDLE_VALUE) {
				CloseHandle(fileHandle);
				fileHandle = NULL;
			}

			return img;
		}
	
		return NULL;
	}

	void featureArrayToString(std::string& str, PEImgDetails* pdata) {
		int featureArraySize = sizeof(pdata->fullFeatureArr) / sizeof(pdata->fullFeatureArr[0]);
		int featureArraySizeLessOne = featureArraySize - 1;
		str.append(std::to_string(featureArraySize) + ",");
		for (int i = 0; i < featureArraySize; i++) {
			if (pdata->fullFeatureArr[i] == 1) {
				if (i == featureArraySizeLessOne)
					str.append("1");
				else
					str.append("1,");
			}
			else  if (pdata->fullFeatureArr[i] == 0) {
				if (i == featureArraySizeLessOne)
					str.append("0");
				else
					str.append("0,");
			}
			else  if (pdata->fullFeatureArr[i] == -1) {
				if (i == featureArraySizeLessOne)
					str.append("-1");
				else
					str.append("-1,");
			}
			else {
				if (i == featureArraySizeLessOne)
					str.append(std::to_string(pdata->fullFeatureArr[i]));
				else {
					str.append(std::to_string(pdata->fullFeatureArr[i]));
					str.append(",");
				}
			}
		}
	}
	void impArrayToString(std::string& str, PEImgDetails* pdata) {
		int ImpArraySize = sizeof(pdata->impFeatureArr) / sizeof(pdata->impFeatureArr[0]);
		int ImpArraySizeLessOne = ImpArraySize - 1;
		str.append(std::to_string(ImpArraySize) + ",");
		for (int i = 0; i < ImpArraySize; i++) {
			if (pdata->impFeatureArr[i] == 1) {
				if (i == ImpArraySizeLessOne)
					str.append("1");
				else
					str.append("1,");
			}
			else if (pdata->impFeatureArr[i] == 0) {
				if (i == ImpArraySizeLessOne)
					str.append("0");
				else
					str.append("0,");
			}
			else {
				if (i == ImpArraySizeLessOne)
					str.append(std::to_string(pdata->impFeatureArr[i]));
				else {
					str.append(std::to_string(pdata->impFeatureArr[i]));
					str.append(",");
				}
			}
		}
	}

	void structToProtoPEImgData(struct PEImgDetails* img, ImgDetails* data) {
		if (img->publisher) { data->set_publisher(img->publisher); }
		else { data->set_publisher("n/a"); }

		if (img->cataFile) { data->set_catafile(img->cataFile); }
		else { data->set_catafile("n/a"); }

		if (img->timeStamp)data->set_timestamp(img->timeStamp);
		else { data->set_timestamp("n/a"); }

		if (img->vSignChainVersion)data->set_vsignchainversion(img->vSignChainVersion);
		else { data->set_vsignchainversion("n/a"); }

		if (img->digestAlgorithm)data->set_digestalgorithm(img->digestAlgorithm);
		else { data->set_digestalgorithm("n/a"); }

		if (img->imphaseHash)data->set_imphase_hash(img->imphaseHash);
		else { data->set_imphase_hash("n/a"); }

		if (img->imphashString)data->set_imphash_string(img->imphashString);
		else { data->set_imphash_string("n/a"); }

		if (img->permission)data->set_permission(img->permission);
		else { data->set_permission("n/a"); }

		if (img->company)data->set_company(img->company);
		else { data->set_company("n/a"); }

		if (img->fileDescription)data->set_description(img->fileDescription);
		else { data->set_description("n/a"); }

		if (img->product)data->set_product(img->product);
		else { data->set_product("n/a"); }

		if (img->internalName)data->set_internalname(img->internalName);
		else { data->set_internalname("n/a"); }

		if (img->copyRights)data->set_copyrights(img->copyRights);
		else { data->set_copyrights("n/a"); }

		if (img->orgFileName)data->set_orgfilename(img->orgFileName);
		else { data->set_catafile("n/a"); }

		if (img->productVersion)data->set_productversion(img->productVersion);
		else { data->set_productversion("n/a"); }

		if (img->fileVersion)data->set_fileversion(img->fileVersion);
		else { data->set_fileversion("n/a"); }

		if (img->mimeType)data->set_mimetype(img->mimeType);
		else { data->set_mimetype("n/a"); }

		if (img->fileTypeExt)data->set_filetypeext(img->fileTypeExt);
		else { data->set_filetypeext("n/a"); }

		if (img->writeTime)data->set_writetime(img->writeTime);
		else { data->set_writetime("n/a"); }

		if (img->accessTime)data->set_accesstime(img->accessTime);
		else { data->set_accesstime("n/a"); }

		if (img->createTime)data->set_createtime(img->createTime);
		else { data->set_createtime("n/a"); }

		if (img->MD5value)data->set_md5le_buffer(img->MD5value);
		else { data->set_md5le_buffer("n/a"); }

		if (img->SHA1value)data->set_sha1_buffer(img->SHA1value);
		else { data->set_sha1_buffer("n/a"); }

		if (img->SHA256value)data->set_sha256_buffer(img->SHA256value);
		else { data->set_sha256_buffer("n/a"); }

		if (img->SHA512value)data->set_sha512_buffer(img->SHA512value);
		else { data->set_sha512_buffer("n/a"); }

		if (img->status)data->set_status(img->status);
		else { data->set_status("n/a"); }

		if (img->thumbprint)data->set_thumbprint(img->thumbprint);
		else { data->set_thumbprint("n/a"); }

		if (img->signAlg)data->set_sign_alg(img->signAlg);
		else { data->set_sign_alg("n/a"); }

		if (img->fileSize)data->set_filesize(img->fileSize);
		if (img->signType) {
			if (strcmp(img->signType, "CATALOG") == 0) {
				data->set_filetype(1);
			}

			else if (strcmp(img->signType, "Embeded") == 0) {
				data->set_filetype(2);
			}
			else {
				data->set_filetype(0);

			}
		}
		data->set_numberofcertchains(0);
		if (img->characteristics)
			data->set_characteristics(img->characteristics);

		data->set_signtype(img->verified);
		data->set_errorcode(img->errorCode);
		data->set_ismalware(img->isMalware);
		data->set_confidence(img->mcAnalysis.combineprob);
		if (img->importFunctionString) data->set_importfunctionstring(img->importFunctionString);
		else { data->set_importfunctionstring("n/a"); }

		if (img->mcAnalysis.patternString) {
			data->set_patternstring(img->mcAnalysis.patternString);
		}

		data->set_patternoffset((int32_t)img->mcAnalysis.patternOffset);
		if (img->errorCodeStr) {
			data->set_errorcodestring(img->errorCodeStr);
		}
		else {
			data->set_errorcodestring("n/a");
		}
		// feature array and import array change
		std::string  featureArrayStr, importArrayStr;
		featureArrayToString(featureArrayStr, img);
		impArrayToString(importArrayStr, img);
		data->set_featurearray(featureArrayStr);
		data->set_importarray(importArrayStr);

	}

	MMapAVLLib* initCatchUp(std::wstring folderPath) {
		if (catchUpForFPFlag == TRUE) {
			return catchUpForFP;
		}
		MMapAVLLib* catchUpForFPMap = new MMapAVLLib();
		if (catchUpForFPMap == NULL) {
			return NULL;
		}

		folderPath = folderPath + L"\\catchDataFP.dat";
		if (catchUpForFPMap->InitializeMMapAVLLib(folderPath.c_str(), 4)) {
			catchUpForFPFlag = TRUE;
			//TestUtils::print((L"[SUCCESS] InitializeMMapAVLLib Init Success FolderPath: " + folderPath).c_str());
			return catchUpForFPMap;
		}
		else {
			TestUtils::print((L"[FAILURE] InitializeMMapAVLLib Init Failed FolderPath: " + folderPath + L" , ErrorNo: " + std::to_wstring(GetLastError()).c_str()));
			return NULL;
		}
	}


	void putDataInCatchUp(ImgDetails imgData,ImgDetails* newImgData) {
		size_t size = imgData.ByteSizeLong();
		char* buffer = (char*)malloc(size);
		imgData.SerializeToArray((char*)buffer,(int) size);
		newImgData->ParseFromArray((char*)buffer, (int)size);
		catchUpForFP->PutData(imgData.sha256_buffer(), (char*)buffer,(unsigned long) size);
		if (buffer)
			free(buffer);
	}

	void getDataInCatchUp(ImgDetails* newImgData, ImgDetails* imgData) {
			if (catchUpForFP != NULL) {
				char* node = NULL;
				int Sizeofdata = 20000;

				while (1) {
					int AVLResult = 1;
					node = (char*)malloc((Sizeofdata) * sizeof(char));
					if (node == NULL) {
						TestUtils::print(L"[FAILURE] malloc failed for node");
						break;
					}
					memset(node, '\0', sizeof(char) * Sizeofdata);

					size_t dataLength = 0;
					AVLResult = catchUpForFP->Fetchstring(newImgData->sha256_buffer(), node, Sizeofdata, &dataLength);

					if (AVLResult == ME_AVL_NO_DATA) // new hash 
					{
						putDataInCatchUp(*newImgData,imgData);
						TestUtils::print((L"New SHA256 found during get & insertion skipped for this sha256" + AnsiToUnicode(newImgData->sha256_buffer())).c_str());
						break;
					}
					else if (AVLResult == ME_AVL_SUCCESS) {
						imgData->ParseFromArray((char*)node, (int)dataLength);
						break;
					}
					else
					{
						Sizeofdata = Sizeofdata + 5000;
						if (node != NULL)
						{
							free(node);
							node = NULL;
							continue;
						}
						break;
					}

				}

				if (node != NULL) {
					free(node);
					node = NULL;
				}
			}
	}
	
	int compareTwoImgDetails(ImgDetails * data1, ImgDetails * data2) {
			if (data1 == NULL || data2 == NULL) {
				TestUtils::print(L"Invalid Data1 or Data2");
				return EXIT_FAILURE;
			}
			int mismatchFound = 0;


			if (data1->publisher() != data2->publisher()) {
				TestUtils::print((L"Publisher Mismatch \t" + AnsiToUnicode(data1->publisher()) + L"\t" + AnsiToUnicode(data2->publisher())).c_str());
				mismatchFound = 1;

			}

			if (data1->catafile() != data2->catafile()) {
				TestUtils::print((L"CataFile Mismatch \t" + AnsiToUnicode(data1->catafile()) + L"\t" + AnsiToUnicode(data2->catafile())).c_str());
				mismatchFound = 1;

			}

			if (data1->vsignchainversion() != data2->vsignchainversion()) {
				TestUtils::print((L"VSignChainVersion Mismatch \t" + AnsiToUnicode(data1->vsignchainversion()) + L"\t" + AnsiToUnicode(data2->vsignchainversion())).c_str());
				mismatchFound = 1;

			}

			if (data1->digestalgorithm() != data2->digestalgorithm()) {
				TestUtils::print((L"DigestAlgorithm Mismatch \t" + AnsiToUnicode(data1->digestalgorithm()) + L"\t" + AnsiToUnicode(data2->digestalgorithm())).c_str());
				mismatchFound = 1;

			}

			if (data1->imphase_hash() != data2->imphase_hash()) {
				TestUtils::print((L"ImphaseHash Mismatch \t" + AnsiToUnicode(data1->imphase_hash()) + L"\t" + AnsiToUnicode(data2->imphase_hash())).c_str());
				mismatchFound = 1;

			}

			if (data1->imphash_string() != data2->imphash_string()) {
				TestUtils::print((L"ImpHashString Mismatch \t" + AnsiToUnicode(data1->imphash_string()) + L"\t" + AnsiToUnicode(data2->imphash_string())).c_str());
				mismatchFound = 1;

			}

			if (data1->permission() != data2->permission()) {
				TestUtils::print((L"Permission Mismatch \t" + AnsiToUnicode(data1->permission()) + L"\t" + AnsiToUnicode(data2->permission())).c_str());
				mismatchFound = 1;

			}

			if (data1->company() != data2->company()) {
				TestUtils::print((L"Company Mismatch \t" + AnsiToUnicode(data1->company()) + L"\t" + AnsiToUnicode(data2->company())).c_str());
				mismatchFound = 1;

			}

			if (data1->description() != data2->description()) {
				TestUtils::print((L"Description Mismatch \t" + AnsiToUnicode(data1->description()) + L"\t" + AnsiToUnicode(data2->description())).c_str());
				mismatchFound = 1;

			}

			if (data1->product() != data2->product()) {
				TestUtils::print((L"Product Mismatch \t" + AnsiToUnicode(data1->product()) + L"\t" + AnsiToUnicode(data2->product())).c_str());
				mismatchFound = 1;

			}

			if (data1->internalname() != data2->internalname()) {
				TestUtils::print((L"InternalName Mismatch \t" + AnsiToUnicode(data1->internalname()) + L"\t" + AnsiToUnicode(data2->internalname())).c_str());
				mismatchFound = 1;

			}

			if (data1->copyrights() != data2->copyrights()) {
				TestUtils::print((L"Copyrights Mismatch \t" + AnsiToUnicode(data1->copyrights()) + L"\t" + AnsiToUnicode(data2->copyrights())).c_str());
				mismatchFound = 1;

			}

			if (data1->orgfilename() != data2->orgfilename()) {
				TestUtils::print((L"OrgFileName Mismatch \t" + AnsiToUnicode(data1->orgfilename()) + L"\t" + AnsiToUnicode(data2->orgfilename())).c_str());
				mismatchFound = 1;

			}

			if (data1->productversion() != data2->productversion()) {
				TestUtils::print((L"ProductVersion Mismatch \t" + AnsiToUnicode(data1->productversion()) + L"\t" + AnsiToUnicode(data2->productversion())).c_str());
				mismatchFound = 1;

			}

			if (data1->fileversion() != data2->fileversion()) {
				TestUtils::print((L"FileVersion Mismatch \t" + AnsiToUnicode(data1->fileversion()) + L"\t" + AnsiToUnicode(data2->fileversion())).c_str());
				mismatchFound = 1;

			}

			if (data1->mimetype() != data2->mimetype()) {
				TestUtils::print((L"MimeType Mismatch \t" + AnsiToUnicode(data1->mimetype()) + L"\t" + AnsiToUnicode(data2->mimetype())).c_str());
				mismatchFound = 1;

			}

			if (data1->filetypeext() != data2->filetypeext()) {
				TestUtils::print((L"FileTypeExt Mismatch \t" + AnsiToUnicode(data1->filetypeext()) + L"\t" + AnsiToUnicode(data2->filetypeext())).c_str());
				mismatchFound = 1;

			}

			if (data1->md5le_buffer() != data2->md5le_buffer()) {
				TestUtils::print((L"MD5 Buffer Mismatch \t" + AnsiToUnicode(data1->md5le_buffer()) + L"\t" + AnsiToUnicode(data2->md5le_buffer())).c_str());
				mismatchFound = 1;

			}

			if (data1->sha1_buffer() != data2->sha1_buffer()) {
				TestUtils::print((L"SHA1 Buffer Mismatch \t" + AnsiToUnicode(data1->sha1_buffer()) + L"\t" + AnsiToUnicode(data2->sha1_buffer())).c_str());
				mismatchFound = 1;

			}

			if (data1->sha256_buffer() != data2->sha256_buffer()) {
				TestUtils::print((L"SHA256 Buffer Mismatch \t" + AnsiToUnicode(data1->sha256_buffer()) + L"\t" + AnsiToUnicode(data2->sha256_buffer())).c_str());
				mismatchFound = 1;

			}

			if (data1->sha512_buffer() != data2->sha512_buffer()) {
				TestUtils::print((L"SHA512 Buffer Mismatch \t" + AnsiToUnicode(data1->sha512_buffer()) + L"\t" + AnsiToUnicode(data2->sha512_buffer())).c_str());
				mismatchFound = 1;

			}

			if (data1->status() != data2->status()) {
				TestUtils::print((L"Status Mismatch \t" + AnsiToUnicode(data1->status()) + L"\t" + AnsiToUnicode(data2->status())).c_str());
				mismatchFound = 1;

			}

			if (data1->thumbprint() != data2->thumbprint()) {
				TestUtils::print((L"Thumbprint Mismatch \t" + AnsiToUnicode(data1->thumbprint()) + L"\t" + AnsiToUnicode(data2->thumbprint())).c_str());
				mismatchFound = 1;

			}

			if (data1->sign_alg() != data2->sign_alg()) {
				TestUtils::print((L"Sign Algorithm Mismatch \t" + AnsiToUnicode(data1->sign_alg()) + L"\t" + AnsiToUnicode(data2->sign_alg())).c_str());
				mismatchFound = 1;

			}

			if (data1->filesize() != data2->filesize()) {
				TestUtils::print((L"File Size Mismatch \t" + std::to_wstring(data1->filesize()) + L"\t" + std::to_wstring(data2->filesize())).c_str());
				mismatchFound = 1;

			}

			if (data1->filetype() != data2->filetype()) {
				TestUtils::print((L"File Type Mismatch \t" + std::to_wstring(data1->filetype()) + L"\t" + std::to_wstring(data2->filetype())).c_str());
				mismatchFound = 1;

			}

			if (data1->numberofcertchains() != data2->numberofcertchains()) {
				TestUtils::print((L"Number of Cert Chains Mismatch \t" + std::to_wstring(data1->numberofcertchains()) + L"\t" + std::to_wstring(data2->numberofcertchains())).c_str());
				mismatchFound = 1;

			}

			if (data1->characteristics() != data2->characteristics()) {
				TestUtils::print((L"Characteristics Mismatch \t" + std::to_wstring(data1->characteristics()) + L"\t" + std::to_wstring(data2->characteristics())).c_str());
				mismatchFound = 1;

			}

			if (data1->signtype() != data2->signtype()) {
				TestUtils::print((L"Sign Type Mismatch \t" + std::to_wstring(data1->signtype()) + L"\t" + std::to_wstring(data2->signtype())).c_str());
				mismatchFound = 1;

			}

			if (data1->errorcode() != data2->errorcode()) {
				TestUtils::print((L"Error Code Mismatch \t" + std::to_wstring(data1->errorcode()) + L"\t" + std::to_wstring(data2->errorcode())).c_str());
				mismatchFound = 1;

			}



			if (data1->confidence() != data2->confidence()) {
				TestUtils::print((L"Confidence Mismatch \t" + std::to_wstring(data1->confidence()) + L"\t" + std::to_wstring(data2->confidence())).c_str());
				mismatchFound = 1;

			}
			if (data1->featuremalware() != data2->featuremalware()) {
				TestUtils::print((L"Feature Malware Mismatch \t" + std::to_wstring(data1->featuremalware()) + L"\t" + std::to_wstring(data2->featuremalware())).c_str());
				mismatchFound = 1;

			}


			if (data1->errorcode() != data2->errorcode()) {
				TestUtils::print((L"Error Code Mismatch \t" + std::to_wstring(data1->errorcode()) + L"\t" + std::to_wstring(data2->errorcode())).c_str());
				mismatchFound = 1;

			}

			if (data1->importfunctionstring() != data2->importfunctionstring()) {
				TestUtils::print((L"Import Function String Mismatch \t" + std::wstring(data1->importfunctionstring().begin(), data1->importfunctionstring().end()) + L"\t" + std::wstring(data2->importfunctionstring().begin(), data2->importfunctionstring().end())).c_str());
				mismatchFound = 1;

			}

			if (data1->patternstring() != data2->patternstring()) {
				TestUtils::print((L"Pattern String Mismatch \t" + std::wstring(data1->patternstring().begin(), data1->patternstring().end()) + L"\t" + std::wstring(data2->patternstring().begin(), data2->patternstring().end())).c_str());
				mismatchFound = 1;

			}

			if (data1->patternoffset() != data2->patternoffset()) {
				TestUtils::print((L"Pattern Offset Mismatch \t" + std::to_wstring(data1->patternoffset()) + L"\t" + std::to_wstring(data2->patternoffset())).c_str());
				mismatchFound = 1;

			}

			if (data1->errorcodestring() != data2->errorcodestring()) {
				TestUtils::print((L"Error Code String Mismatch \t" + std::wstring(data1->errorcodestring().begin(), data1->errorcodestring().end()) + L"\t" + std::wstring(data2->errorcodestring().begin(), data2->errorcodestring().end())).c_str());
				mismatchFound = 1;

			}

			if (data1->importarray() != data2->importarray()) {
				TestUtils::print((L"Import Array Mismatch \t" + std::wstring(data1->importarray().begin(), data1->importarray().end()) + L"\t" + std::wstring(data2->importarray().begin(), data2->importarray().end())).c_str());
				mismatchFound = 1;

			}

			if (data1->featurearray() != data2->featurearray()) {
				TestUtils::print((L"Feature Array Mismatch \t" + std::wstring(data1->featurearray().begin(), data1->featurearray().end()) + L"\t" + std::wstring(data2->featurearray().begin(), data2->featurearray().end())).c_str());
				mismatchFound = 1;

			}
			if (mismatchFound) {
				std::cout << data2->filepath() << std::endl;
				TestUtils::print((wchar_t*)(AnsiToUnicode(data2->filepath()).c_str()));
				Assert::AreEqual(mismatchFound, 0, L"mismatch found");
			}
			// string compare in cpp
			//if (strcmp(data1->createtime().c_str(), data2->createtime().c_str()) != 0) {
			//	TestUtils::print((L"Create Time Mismatch \t" + AnsiToUnicode(data1->createtime()) + L"\t" + AnsiToUnicode(data2->createtime())).c_str());
			//	mismatchFound = 1;
			//}
			//if (data1->writetime() != data2->writetime()) {
			//	TestUtils::print((L"Write Time Mismatch \t" + AnsiToUnicode(data1->writetime()) + L"\t" + AnsiToUnicode(data2->writetime())).c_str());
			//	mismatchFound = 1;
			//}
			/*if (data1->ismalware() != data2->ismalware()) {
				TestUtils::print((L"Is Malware Mismatch \t" + std::to_wstring(data1->ismalware()) + L"\t" + std::to_wstring(data2->ismalware())).c_str());
				mismatchFound = 1;

			}*/

			if (data1->timestamp() != data2->timestamp()) {
				TestUtils::print((L"Timestamp Mismatch \t" + AnsiToUnicode(data1->timestamp()) + L"\t" + AnsiToUnicode(data2->timestamp())).c_str());
				mismatchFound = 1;
			}

			return mismatchFound ? EXIT_FAILURE : EXIT_SUCCESS;

	}

	int getFeatureFromCatchAndCompare(ImgDetails* newImgData) {
		ImgDetails oldImgData;
		getDataInCatchUp(newImgData, &oldImgData);
		int retValue = compareTwoImgDetails(&oldImgData, newImgData);
		return EXIT_SUCCESS;
	}


	int featureExtractAndPutAVL(std::wstring filePath, ImgDetails* imgData) {
		PEImgDetails* img = startPEWrapper(filePath);
		if (img != NULL) {

			std::wcout << filePath << std::endl;
			structToProtoPEImgData(img, imgData);

			getFeatureFromCatchAndCompare(imgData);

			int freeImgDetailsWrapperValue = freeImgDetailsWrapper(img);
			Assert::AreEqual(freeImgDetailsWrapperValue, EXIT_SUCCESS, L"FP::freeImgDetailsWrapper Failed");
			return 1;
		}
		else {
			TestUtils::print((L"invalid filepath found " + filePath).c_str());
			iterateFolderAndExtractFeature((WCHAR*)filePath.c_str(), 1);
			return 0;
		}
	}

	__declspec(noinline) int iterateFolderAndExtractFeature(WCHAR* rootDir, BOOL subDirectories) {
		BOOL bSubdirectory = FALSE;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		WIN32_FIND_DATAW FileInformation;
		size_t strPatternLen = wcslen(rootDir) + 6;
		WCHAR* strPattern = (WCHAR*)calloc(strPatternLen, sizeof(WCHAR));

		if (strPattern == NULL) {
			wprintf(L"Memory allocation failed for strPattern\n");
			return -1;
		}

		wcscpy_s(strPattern, strPatternLen, rootDir);
		wcscat_s(strPattern, strPatternLen, L"\\*.*");

		hFile = FindFirstFileW(strPattern, &FileInformation);
		if (hFile == INVALID_HANDLE_VALUE) {
			//wprintf(L"FindFirstFileW failed for pattern %s\n", strPattern);
			free(strPattern);
			return -1;
		}

		do {
			if (FileInformation.cFileName[0] != '.') {
				size_t strFilePathLen = wcslen(rootDir) + wcslen(FileInformation.cFileName) + 3;
				WCHAR* strFilePath = (WCHAR*)calloc(strFilePathLen, sizeof(WCHAR));

				if (strFilePath == NULL) {
					wprintf(L"Memory allocation failed for strFilePath\n");
					FindClose(hFile);
					free(strPattern);
					return -1;
				}

				wcscpy_s(strFilePath, strFilePathLen, rootDir);
				wcscat_s(strFilePath, strFilePathLen, L"\\");
				wcscat_s(strFilePath, strFilePathLen, FileInformation.cFileName);

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					if (subDirectories) {
						iterateFolderAndExtractFeature(strFilePath, subDirectories);
					}
					else {
						bSubdirectory = TRUE;
					}
				}
				else {
					ImgDetails oldData;
					featureExtractAndPutAVL(strFilePath, &oldData);
				}
				free(strFilePath);
			}
		} while (FindNextFileW(hFile, &FileInformation) == TRUE);

		FindClose(hFile);
		free(strPattern);

		return 0;
	}


};


