#ifndef QUICKR_MC_WORKERMANAGER_H
#define QUICKR_MC_WORKERMANAGER_H
#include <iostream>
#include <thread>
#include <vector>

#include "./Worker.h"
#include "../models/FileMeta.h"


namespace quickrengine {

	class WorkerManager
	{
	public:
		WorkerManager();


        size_t getNumWorkers() const;

        void start(unsigned int wantedWorkers);
        void stop();
        void join();
        void scan(const std::wstring& filepath) const;

        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> getResultQueue();
        unsigned long getFilesProcessed() const;

    private:
        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> resultQueue{ nullptr };
        std::shared_ptr<queue::Queue<std::wstring>> fileWorkQueue{ nullptr };

        std::vector<std::shared_ptr<Worker>> workers;
        std::vector<std::thread> workerThreads;

        wchar_t* winTrustedCertificatePath = (wchar_t*)L"Resource\\WinTrustedCertificates";
        const wchar_t* ruleEnginePath = L"d:\\yara.yar";
	};


}

#endif

