#include "Worker.h"
#include <cassert>

namespace quickrengine {

	Worker::Worker(std::shared_ptr<queue::Queue<std::wstring>> queue, std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> rqueue, long long _id) : workQueue(queue), resultQueue(rqueue), running_id(_id)
    {
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


    unsigned long Worker::getFilesProcessed()
    {
        return filesProcessed;
    }

	void Worker::stop()
	{
		running = false;
	}

}
