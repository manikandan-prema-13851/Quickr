#include<iostream>
#include<Windows.h>
namespace quickrengine{
	namespace test {
		std::wstring GetTempDirectoryPath();
		std::wstring GetTempFilePath();
		bool removeDirectory(const std::wstring& dirPath);
		bool createDirectory(const std::wstring& dirPath);
	}
}
