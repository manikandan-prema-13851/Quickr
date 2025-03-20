#ifndef QUICKR_MC_WORKERMANAGER_H
#define QUICKR_MC_WORKERMANAGER_H
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>

#include "./Worker.h"
#include "./WatchdogWorker.h"
#include "../models/FileMeta.h"

namespace quickrengine {
    class WatchdogWorker; // Forward declaration

    class WorkerManager
    {
        friend class WatchdogWorker;
    public:
        WorkerManager();
        ~WorkerManager();

        size_t getNumWorkers() const;

        void start(unsigned int wantedWorkers);
        void stop();
        void join();
        void scan(const std::wstring& filepath) const;

        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> getResultQueue();
        unsigned long getFilesProcessed() const;

        size_t getWatchdogRestartCount() const;
        void handleThreadRestart(int workerIndex);

    protected:
        HANDLE createWorkerThread(int);

        std::vector<std::shared_ptr<Worker>> workers;
        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> resultQueue{ nullptr };
        std::shared_ptr<queue::Queue<std::wstring>> fileWorkQueue{ nullptr };
        // Watchdog components
        std::unique_ptr<WatchdogWorker> watchdog{ nullptr };
        HANDLE watchdogThread = NULL;
        std::chrono::seconds workerTimeout{ 30 }; // 30 seconds timeout

        std::vector<HANDLE> workerThreads;
        std::mutex threadMutex;

    private:



        wchar_t* winTrustedCertificatePath = (wchar_t*)L"Resource\\WinTrustedCertificates";
        const wchar_t* ruleEnginePath = L"d:\\yara.yar";
	};


}

#endif

