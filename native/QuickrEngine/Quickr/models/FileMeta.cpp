#include "FileMeta.h"
#include <windows.h>
#include "chrono"

namespace quickrengine {

    static __int64 currentTimeMillis() {
        FILETIME f;
        GetSystemTimeAsFileTime(&f);
        (long long)f.dwHighDateTime;
        __int64 nano = ((__int64)f.dwHighDateTime << 32LL) + (__int64)f.dwLowDateTime;
        return (nano - 116444736000000000LL) / 10000;
    }

    FileMeta::FileMeta(FileType _type, long _size, unsigned long long _dev, unsigned long long _ino,const std::wstring& _filepath)
        : dev(_dev), ino(_ino), type(_type), size(_size), filepath(_filepath), isFinished(!isDirectory())
    {
    
        currentmillisec = currentTimeMillis();
       
    }


    const std::vector<std::wstring>& FileMeta::children()
    {
        if (hasCachedChildren)
        {
            return cachedChildren;
        }

        if (type != FileType::directory)
        {
            hasCachedChildren = true;
            return cachedChildren;
        }

        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((filepath + L"\\*").c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE)
        {
            hasCachedChildren = true;
            return cachedChildren;
        }

        std::vector<std::wstring> childPaths;

        do
        {
            std::wstring fileName = findData.cFileName;

            // Ignore "." and ".."
            if (fileName != L"." && fileName != L"..")
            {
                childPaths.push_back(filepath + L"\\" + fileName);
            }

        } while (FindNextFileW(hFind, &findData) != 0);

        FindClose(hFind);

        cachedChildren = childPaths;
        hasCachedChildren = true;
        return cachedChildren;
    }

    std::shared_ptr<FileMeta> FileMeta::fromPath(const std::wstring& filepath)
    {
        WIN32_FILE_ATTRIBUTE_DATA fileData;

        if (!GetFileAttributesExW(filepath.c_str(), GetFileExInfoStandard, &fileData))
        {
            // File not found or inaccessible
            return std::make_shared<FileMeta>(FileType::unknown, 0, 0, 0, filepath);
        }

        FileType type;

        if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            type = FileType::directory;
        }
        else if (fileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            type = FileType::symbolic_link;
        }
        else
        {
            type = FileType::regular_file;
        }

        uint64_t fileSize = (static_cast<uint64_t>(fileData.nFileSizeHigh) << 32) | fileData.nFileSizeLow;

        return std::make_shared<FileMeta>(type, fileSize, 0, 0, filepath);
    }

    bool FileMeta::isDirectory() const
    {
        return type == FileType::directory;
    }

    bool FileMeta::getHasCachedChildren() const
    {
        return hasCachedChildren;
    }

    void FileMeta::setCachedChildren(const std::vector<std::wstring>& _cachedChildren)
    {
        hasCachedChildren = true;
        cachedChildren = _cachedChildren;
    }

}