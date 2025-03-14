# PE Parser 

This project demonstrates scanning and analyzing Portable Executable (PE) files to detect anomalies, verify signatures, and compute cryptographic hashes. It leverages trusted certificates and YARA rules for detailed malware detection.

<details>
<summary>
How To Use File Parser
</summary>

(1) Include Required Libraries

- #pragma comment(lib, "Crypt32.lib")
- #pragma comment(lib, "Bcrypt.lib")
- #pragma comment(lib, "Wintrust.lib")
- #pragma comment(lib, "FileParser.lib")

(2) Include files

- extern "C" {
-    #include "FileParser.h"
-    #include "../FeatureExtractor/FeatureHeader.h"
- }

(3) Init File Parser

- MalwareDetectionEngine malDetEngine = {0};
- int initPEParserFlag = initPEParser(&malDetEngine, winTrustedCertificatePath);
- int initRuleEngineFlag = initRuleEngine(&malDetEngine, yaraRuleFilePath);

- if (initPEParserFlag == 1 || initRuleEngineFlag == 1) {
-     printf("Initialization Failed\n");
- }


(4) File Parser call

- struct PEImgDetails* img = startPE(filePath, &malDetEngine, mappedFileView, enableYaraScan, NULL);

(5) Print And Free File Parser details

- printImgDetails(img, verbose);
- freeImgDetails(img);


</details>

<details><summary>Sample data for Notepad.exe</summary>

- filePath:        c:\windows\notepad.exe
- fileSize:        201216
- publisher:       Microsoft Root Certificate Authority 2010
- timeStamp:       2022/07/21 07:06:42
- vSignChainVersion:       (null)
- digestAlgorithm:         (null)
- imphaseHash:     (null)
- imphashString:   (null)
- permission:      rwxrwxrwx
- company:         Microsoft Corporation
- product:         Microsoft« Windows« Operating System
- internalName:    Notepad
- copyRights:      ⌐ Microsoft Corporation. All rights reserved.
- orgFileName:     NOTEPAD.EXE
- productVersion:  10.0.19041.1865
- fileVersion:     10.0.19041.1865 (WinBuild.160101.0800)
- fileDescription:         Notepad
- mimeType:        application/octet-stream
- fileTypeExt:     EXE
- writeTime:       10/08/2022 16:28:54
- accessTime:      22/09/2022 11:47:14
- createTime:      10/08/2022 16:28:54
- MD5:     27F71B12CB585541885A31BE22F61C83
- SHA1:    D05DEFE2C8EFEF10ED5F1361760FA0AE41FA79F5
- SHA256:  F9D9B9DED9A67AA3CFDBD5002F3B524B265C4086C188E1BE7C936AB25627BF01
- SHA512:  15E1782612460D63C0BFFE464296E6974F9606A94075AF2BC4D880145F2EE86953675DE90264EB04DF8607A99CFC02C15A5771A6C923D8FBC8428F7513CE9C75
- status:  SUCCESS
- Thumbprint:      3b1efd3a66ea28b16697394703a72ca340a05bd5
- SignAlg:         sha256RSA(RSA)
- SignType         CATALOG
- Verified:        1
- CataFile:        C:\Windows\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~~10.0.19041.1865.cat
- Characteristics:         34
- fullFeatureArr: Float Array contains 2224 Values
- impFeatureArr: Float Array Contains 1230 Values
- errorCode: Indicates an error code returned during the analysis process. If no error, this field will be 0
- importFunctionString: A concatenated string representation of all imported functions from the Import Address Table (IAT) of the PE file. For example: kernel32.dll:CreateFileW, kernel32.dll:ReadFile
- filePathW: The full file path in wide-character (Unicode) format, e.g., C:\Windows\Notepad.exe.
- patternString: A string representation of specific patterns detected during the YARA rule scanning or heuristic analysis. Example: MZHeaderPattern, SuspiciousResourcePattern
- patternOffset: The file offset where the pattern was detected. For example: 0x00001000.
- errorCodeStr: A textual description of the error code if an error occurred during processing
</details>

<details>
<summary>Unit Testing & Coverage Testing</summary>

- [Release vs Debug](https://one.zoho.com/zohoone/zohocorp/home/cxapp/learn/portal/zohocorp/knowledge/manual/design-and-development/article/test)
- [Download this file and extract resource folder](https://workdrive.zoho.com/file/0nq5bfe2ba10d5fb24cdca8a8667e26d15e20)
- extract the above resoure and to run use build/run.bat
- for coverage test need to enterprise version ReportGenerator.exe -reports:"tes.xml" -targetdir:"coverageresults" -reporttypes:Html
</details>