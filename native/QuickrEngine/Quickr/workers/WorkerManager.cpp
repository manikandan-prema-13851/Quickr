#include "WorkerManager.h"

namespace quickrengine {

    WorkerManager::WorkerManager() {
        resultQueue = std::make_shared<queue::Queue<std::shared_ptr<FileMeta>>>();
        fileWorkQueue = std::make_shared<queue::Queue<std::wstring>>();
    }

    WorkerManager::~WorkerManager() {
        stop();
        join();
    }

    size_t WorkerManager::getNumWorkers() const {
        return workers.size();
    }

    void WorkerManager::start(unsigned int wantedWorkers)
    {
        stop();

        for (unsigned int i = 0; i < wantedWorkers; i++)
        {
            assert(fileWorkQueue != nullptr);
            assert(resultQueue != nullptr);

            auto worker = std::make_shared<Worker>(fileWorkQueue, resultQueue, i );
            workers.push_back(worker);
            auto thread = std::thread(&Worker::start, worker.get());
            workerThreads.push_back(std::move(thread));
        }

        watchdog = std::make_unique<WatchdogWorker>(workers, workerTimeout);

        watchdogThread = std::thread([this]() {
            watchdog->start();
            });

    }

    void WorkerManager::stop() {
        // Stop the watchdog
        if (watchdog) {
            watchdog->stop();
        }

        // Stop all workers
        for (auto& worker : workers) {
            worker->stop();
        }

        join();

        workers.clear();
        workerThreads.clear();
    }

    void WorkerManager::join() {
        // Join watchdog thread
        if (watchdogThread.joinable()) {
            watchdogThread.join();
        }

        // Join worker threads
        for (auto& thread : workerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }

    void WorkerManager::scan(const std::wstring& filepath) const {
        fileWorkQueue->push(filepath);
    }

    std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> WorkerManager::getResultQueue() {
        return resultQueue;
    }

    unsigned long WorkerManager::getFilesProcessed() const {
        unsigned long total = 0;
        for (const auto& worker : workers) {
            total += worker->getFilesProcessed();
        }
        return total;
    }

    size_t WorkerManager::getWatchdogRestartCount() const {
        return watchdog ? watchdog->getRestartCount() : 0;
    }
}