#include "WorkerManager.h"
namespace quickrengine {

    WorkerManager::WorkerManager()
        : resultQueue(std::make_shared<queue::Queue<std::shared_ptr<FileMeta>>>()),
        fileWorkQueue(std::make_shared<queue::Queue<std::wstring>>())
    {
        
    }

    size_t WorkerManager::getNumWorkers() const
    {
        return workerThreads.size();
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
    }

    void WorkerManager::stop()
    {
        for (const auto& worker : workers)
        {
            worker->stop();
        }

        join();

        workers.clear();
        workerThreads.clear();
    }

    void WorkerManager::join()
    {
        for (auto& workerThread : workerThreads)
        {
            workerThread.join();
        }
    }

    void WorkerManager::scan(const std::wstring& filepath) const
    {
        fileWorkQueue->push(filepath);
    }

    unsigned long WorkerManager::getFilesProcessed() const
    {
        unsigned long filesProcessed = 0;
        for (const auto& worker : workers)
        {
            filesProcessed += worker->getFilesProcessed();
        }
        return filesProcessed;
    }


    std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> WorkerManager::getResultQueue()
    {
        return resultQueue;
    }
}