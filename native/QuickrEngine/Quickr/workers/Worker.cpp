#include "Worker.h"
#include <thread>

namespace quickrengine {

    Worker::Worker(std::shared_ptr<queue::Queue<std::wstring>> queue,
        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> rqueue,
        long long id)
        : workQueue(queue), resultQueue(rqueue), running_id(id) {
    }

    void Worker::start()
    {
        running = true;

        while (running)
        {
            assert(workQueue != nullptr);

            auto maybeFile = workQueue->frontWithTimeout(std::chrono::milliseconds(10));
            // handle worker queue 
            if (maybeFile)
            {
                auto file = maybeFile.value();
                processEntry(file);
            }
            else {
                running = false;
            }
        }
    }

    void Worker::processEntry(std::wstring& _filePath)
    {
        {
            // Update the task start time when starting to process a file
            std::lock_guard<std::mutex> lock(timeMutex);
            taskStartTime = std::chrono::steady_clock::now();
            processing = true;
        }
        if (_filePath == L"/System/Volumes/Data")
        {
            std::shared_ptr<FileMeta> fileEntry = std::make_shared<FileMeta>();
            fileEntry->size = 0;
            fileEntry->filepath = _filePath;
            fileEntry->dev = 0;
            fileEntry->ino = 0;
            fileEntry->isFinished = true;
            fileEntry->type = FileType::unknown;
            resultQueue->push(fileEntry);
            return;
        }
        else{
            auto fileEntry = FileMeta::fromPath(_filePath);
            filesProcessed += 1;
    
            auto& children = fileEntry->children();
            fileEntry->threadId = running_id;
            resultQueue->push(fileEntry);
            for (const auto& child : children)
            {
                workQueue->push(child);
            }
        }

        {
            std::lock_guard<std::mutex> lock(timeMutex);
            processing = false;
        }
    }

    void Worker::stop() {
        running = false;
    }

    unsigned long Worker::getFilesProcessed() {
        return filesProcessed;
    }

    bool Worker::isHung(const std::chrono::seconds& timeout) const {
        std::lock_guard<std::mutex> lock(timeMutex);
        if (!processing) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - taskStartTime);
        auto flag = duration > timeout; 
        auto temp = taskStartTime;
        //Debugging All Values
        std::wcout << L"---------------------- DEBUG OUTPUT ----------------------\n";
        std::wcout << L"taskStartTime: " << taskStartTime.time_since_epoch().count() << L" ticks\n";
        std::wcout << L"now:           " << now.time_since_epoch().count() << L" ticks\n";
        std::wcout << L"duration:      " << duration.count() << L" seconds\n";
        std::wcout << L"timeout:       " << timeout.count() << L" seconds\n";
        std::wcout << L"flag:          " << flag << L"\n"; // true (1) or false (0)
        std::wcout << L"temp:          " << temp.time_since_epoch().count() << L" ticks\n";
        std::wcout << L"---------------------------------------------------------\n";


        return duration > timeout;
    }

    void Worker::restart() {
        // Mark the current task as completed to prevent duplicate work
        std::lock_guard<std::mutex> lock(timeMutex);
        processing = false;
        // The task will be considered complete but failed
    }

    bool Worker::isProcessing() const {
        std::lock_guard<std::mutex> lock(timeMutex);
        return processing;
    }
}