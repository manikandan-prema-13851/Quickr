#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <quickr/workers/Worker.h>
#include <quickr/workers/WorkerManager.h>
#include <quickr/workers/WatchdogWorker.h>
#include <quickr/queue/Queue.h>

using namespace quickrengine;

// Create a test version of Worker that simulates taking too long to process files
class SlowWorker : public Worker {
public:
    SlowWorker(std::shared_ptr<queue::Queue<std::wstring>> queue,
        std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> rqueue,
        long long id)
        : Worker(queue, rqueue, id) {
    }

    void processEntry(std::wstring& file) override {
        
        {
            processing = true;
            taskStartTime = std::chrono::steady_clock::now();
        }

        if (file.find(L"hang") != std::wstring::npos) {
            std::this_thread::sleep_for(std::chrono::seconds(40));
        }
    
        {
            processing = false;
        }

    }

    void start() {
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
};

class WatchdogTest : public ::testing::Test {
protected:
    void SetUp() override {
        workQueue = std::make_shared<queue::Queue<std::wstring>>();
        resultQueue = std::make_shared<queue::Queue<std::shared_ptr<FileMeta>>>();
        watchdogTimeout = std::chrono::seconds(20);
    }

    std::shared_ptr<queue::Queue<std::wstring>> workQueue;
    std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> resultQueue;
    std::chrono::seconds watchdogTimeout;
};

TEST_F(WatchdogTest, DetectsAndRestartsHungWorker) {
    std::vector<std::shared_ptr<Worker>> workers;

    // Use our SlowWorker instead of regular Worker
    auto worker = std::make_shared<SlowWorker>(workQueue, resultQueue, 0);
    workers.push_back(worker);
    WatchdogWorker watchdog(workers, watchdogTimeout);
    std::thread watchdogThread([&]() {
        watchdog.start();
        });

    // Start the worker
    std::wstring hangFile = L"test_hang_file.txt";
    workQueue->push(hangFile);

    worker->start();
    // Need to wait longer than the watchdog timeout
    std::this_thread::sleep_for(watchdogTimeout + std::chrono::seconds(60));

    watchdog.stop();
    worker->stop();
    watchdogThread.join();
    EXPECT_GT(watchdog.getRestartCount(), 0);
}