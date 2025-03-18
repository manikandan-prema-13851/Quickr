#ifndef QUICKR_MC_WORKER_H
#define QUICKR_MC_WORKER_H

#include <iostream>
#include <string>
#include <chrono>
#include <mutex>
#include <atomic>

#include "../queue/Queue.h"
#include "../models/FileMeta.h"

namespace quickrengine {
    class Worker {
    public:
        Worker(std::shared_ptr<queue::Queue<std::wstring>> queue, std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> rqueue, long long id);

        virtual void start();
        void stop();
        virtual void processEntry(std::wstring& file);
        unsigned long getFilesProcessed();

        // New methods for watchdog functionality
        bool isHung(const std::chrono::seconds& timeout = std::chrono::seconds(30)) const;
        void restart();
        bool isProcessing() const;
        long long getId() const { return running_id; }
        bool isRunning() const { return running; }

        std::shared_ptr<queue::Queue<std::wstring>> getWorkQueue() const { return workQueue; }
        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> getResultQueue() const { return resultQueue; }

    protected:
        std::atomic<bool> running{ false };
        std::atomic<bool> processing{ false }; // Indicates if currently processing a file
        std::atomic<unsigned long> filesProcessed{ 0 };
        std::chrono::steady_clock::time_point taskStartTime;

        long long running_id = 0;

        std::shared_ptr<queue::Queue<std::wstring>> workQueue{ nullptr };
        std::shared_ptr<queue::Queue<std::shared_ptr<quickrengine::FileMeta>>> resultQueue{ nullptr };

    private:
        // Task timing tracking
        mutable std::mutex timeMutex;
    };
}

#endif