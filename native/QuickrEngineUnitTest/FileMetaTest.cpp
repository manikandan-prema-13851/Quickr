#include <gtest/gtest.h>
#include <Quickr/models/FileMeta.h>
#include "TestUtils.h"


TEST(FileEntryTest, CanTellTheSizeOfFiles) {

    std::wstring tempFilePath = quickrmc::test::GetTempFilePath();
    HANDLE hFile = CreateFileW(tempFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_NE(hFile , INVALID_HANDLE_VALUE);

    const char* data = "some stuff here";
    DWORD bytesWritten;
    WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, nullptr);
    CloseHandle(hFile);

    WIN32_FILE_ATTRIBUTE_DATA fileData;
    EXPECT_TRUE(GetFileAttributesExW(tempFilePath.c_str(), GetFileExInfoStandard, &fileData));


	auto entry = quickrengine::FileMeta::fromPath(tempFilePath);
    auto size = entry->size;


	EXPECT_GT(size, 0);
	EXPECT_EQ(static_cast<unsigned long>(size), bytesWritten);
	DeleteFileW(tempFilePath.c_str());

}

TEST(FileEntryTest, CanTellTheSizeOfDirectories) {
    std::wstring tempFilePath = quickrmc::test::GetTempDirectoryPath();
	CreateDirectoryW(tempFilePath.c_str(), nullptr);
	WIN32_FILE_ATTRIBUTE_DATA fileData;
	EXPECT_TRUE(GetFileAttributesExW(tempFilePath.c_str(), GetFileExInfoStandard, &fileData));
    
	auto entry = quickrengine::FileMeta::fromPath(tempFilePath);
	auto size = entry->size;

	EXPECT_EQ(size, 0);
	EXPECT_TRUE(entry->isDirectory());

	RemoveDirectoryW(tempFilePath.c_str());
}


TEST(FileEntryTest, CanListDirectoryChildren) {
	std::wstring tempDirPath = quickrmc::test::GetTempDirectoryPath();
	CreateDirectoryW(tempDirPath.c_str(), nullptr);
	std::wstring tempFile1 = tempDirPath + L"\\file1.txt";
	std::wstring tempFile2 = tempDirPath + L"\\file2.txt";
	HANDLE hFile1 = CreateFileW(tempFile1.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	EXPECT_NE(hFile1, INVALID_HANDLE_VALUE);
	HANDLE hFile2 = CreateFileW(tempFile2.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	EXPECT_NE(hFile2, INVALID_HANDLE_VALUE);
	CloseHandle(hFile1);
	CloseHandle(hFile2);
	auto entry = quickrengine::FileMeta::fromPath(tempDirPath);
	auto children = entry->children();
	EXPECT_EQ(children.size(), 2);
	{
		auto it = std::find(children.begin(), children.end(), tempFile1);
		EXPECT_NE(it, children.end());
		EXPECT_EQ(*it, tempFile1);
	}
	{
		auto it = std::find(children.begin(), children.end(), tempFile2);
		EXPECT_NE(it, children.end());
		EXPECT_EQ(*it, tempFile2);
	}
	DeleteFileW(tempFile1.c_str());
	DeleteFileW(tempFile2.c_str());
	RemoveDirectoryW(tempDirPath.c_str());
}

