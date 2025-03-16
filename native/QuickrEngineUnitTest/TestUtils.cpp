#include "TestUtils.h"


namespace quickrengine::test {

    std::wstring GetTempDirectoryPath()

    {
        wchar_t tempPath[MAX_PATH];
        wchar_t tempDir[MAX_PATH];

        GetTempPathW(MAX_PATH, tempPath);
        swprintf(tempDir, MAX_PATH, L"%s%s", tempPath, L"test-directory");

        return std::wstring(tempDir);
    }

    std::wstring GetTempFilePath()
    {
        wchar_t tempPath[MAX_PATH];
        wchar_t tempFile[MAX_PATH];

        GetTempPathW(MAX_PATH, tempPath);
        GetTempFileNameW(tempPath, L"TEST", 0, tempFile);

        return std::wstring(tempFile);
    }

    bool createDirectory(const std::wstring& dirPath) {
        return CreateDirectory(dirPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    }

    bool removeDirectory(const std::wstring& dirPath) {
        std::wstring searchPath = dirPath + L"\\*";  // Wildcard to search all files/folders
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }

        do {
            std::wstring fileName = findData.cFileName;

            if (fileName != L"." && fileName != L"..") {
                std::wstring filePath = dirPath + L"\\" + fileName;

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Recursively remove subdirectories
                    removeDirectory(filePath);
                }
                else {
                    // Remove files
                    if (!DeleteFileW(filePath.c_str())) {
                        std::wcerr << L"Error: Unable to delete file " << filePath << L" (Error Code: " << GetLastError() << L")\n";
                    }
                }
            }
        } while (FindNextFileW(hFind, &findData) != 0);

        // Check for errors in FindNextFile
        if (GetLastError() != ERROR_NO_MORE_FILES) {
            std::wcerr << L"Error: FindNextFile failed (Error Code: " << GetLastError() << L")\n";
        }

        FindClose(hFind);

        // Remove the directory itself
        if (!RemoveDirectoryW(dirPath.c_str())) {
            std::wcerr << L"Error: Unable to remove directory " << dirPath << L" (Error Code: " << GetLastError() << L")\n";
            return false;
        }

        return true;
    }
}