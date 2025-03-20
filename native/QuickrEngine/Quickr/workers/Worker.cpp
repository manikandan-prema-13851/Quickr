#include "Worker.h"
#include "../QuickrEngine/quickengine_version.h"
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

            auto maybeFile = workQueue->frontWithTimeout(std::chrono::milliseconds(1));
            // handle worker queue 
            if (maybeFile)
            {
                auto file = maybeFile.value();
                processEntry(file);
            }
            else {
                std::lock_guard<std::mutex> lock(timeMutex);
                taskStartTime = std::chrono::steady_clock::now();
                currentFile.clear(); // Store the current file
                processing = false;
            }
        }
    }

    void Worker::processEntry(std::wstring& _filePath)
    {
        {
            // Update the task start time when starting to process a file
            std::lock_guard<std::mutex> lock(timeMutex);
            taskStartTime = std::chrono::steady_clock::now();
            currentFile = _filePath; // Store the current file
            processing = true;
        }
        if (_filePath == L"/System/hang/Data")
        {
#ifdef TEST_MODE
            DEBUG_MSG (L"Test Mode: In /System/Volumes/Data")

            if (_filePath.find(L"hang") != std::wstring::npos) {
                    std::this_thread::sleep_for(std::chrono::seconds(31));
            }

#endif
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
            currentFile.clear();
        }
    }

    void Worker::stop() {
        running = false;
    }

    unsigned long Worker::getFilesProcessed() {
        return filesProcessed;
    }



    std::optional<std::wstring> Worker::getCurrentFile() const {
        std::lock_guard<std::mutex> lock(timeMutex);
        if (processing && !currentFile.empty()) {
            return currentFile;
        }
        return std::nullopt;
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
        DEBUG_MSG(L"---------------------- DEBUG OUTPUT ----------------------");
        DEBUG_MSG(L"taskStartTime: " << taskStartTime.time_since_epoch().count() << L" ticks");
        DEBUG_MSG(L"now:           " << now.time_since_epoch().count() << L" ticks");
        DEBUG_MSG(L"duration:      " << duration.count() << L" seconds");
        DEBUG_MSG(L"timeout:       " << timeout.count() << L" seconds");
        DEBUG_MSG(L"flag:          " << flag << L""); // true (1) or false (0)
        DEBUG_MSG(L"temp:          " << temp.time_since_epoch().count() << L" ticks");
        DEBUG_MSG(L"---------------------------------------------------------");


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