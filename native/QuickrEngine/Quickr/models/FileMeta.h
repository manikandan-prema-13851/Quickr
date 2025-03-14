#ifndef QUICKR_MC_FILEENTRY_H
#define QUICKR_MC_FILEENTRY_H
#include <iostream>
#include <vector>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")

extern "C"
{
#include "FileParser.h"
#include "FeatureExtractor/FeatureHeader.h"
}

namespace quickrengine {
    enum class FileType
    {
        unknown = 0,
        regular_file = 1,
        directory = 2,
        handle = 3,
        symbolic_link = 4,
    };

    class FileMeta {
    public:
        unsigned long long dev = 0;
        unsigned long long ino = 0;
        
        FileType type = FileType::unknown;
        long size = 0; // mcengine
        long long threadId = 0;
        __int64 currentmillisec = 0;
        std::wstring filepath;
        bool isFinished = false;

        FileMeta() = default;
        FileMeta(FileType _type, long _size, unsigned long long _dev, unsigned long long _ino, const std::wstring& _filepath);

        [[nodiscard]] bool isDirectory() const;
        [[nodiscard]] bool getHasCachedChildren() const;

        void setCachedChildren(const std::vector<std::wstring>& cachedChildren);
        const std::vector<std::wstring>& children();

        static std::shared_ptr<FileMeta> fromPath(const std::wstring& filepath);

    private:
        std::vector<std::wstring> cachedChildren{};
        bool hasCachedChildren = false;
    };

}

#endif