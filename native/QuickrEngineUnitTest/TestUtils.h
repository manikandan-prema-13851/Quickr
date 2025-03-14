#include<iostream>
#include<Windows.h>

namespace quickrmc::test {
	std::wstring GetTempDirectoryPath();
	std::wstring GetTempFilePath();
	bool removeDirectory(const std::wstring& dirPath);
	bool createDirectory(const std::wstring& dirPath);
}
