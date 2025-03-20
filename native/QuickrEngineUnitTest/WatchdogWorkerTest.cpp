#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <quickr/workers/Worker.h>
#include <quickr/workers/WorkerManager.h>
#include <quickr/workers/WatchdogWorker.h>
#include <quickr/queue/Queue.h>

using namespace quickrengine;


class TestWorkerManager : public WorkerManager {
public:
    TestWorkerManager() : WorkerManager() {}

    // Override to create SlowWorkers
    void start(unsigned int wantedWorkers) {
        stop();

        for (unsigned int i = 0; i < wantedWorkers; i++)
        {
            HANDLE threadHandle = createWorkerThread(i);
            workerThreads.push_back(threadHandle);
        }

        // Create a thread restart callback
        ThreadRestartCallback callback = [this](int workerIndex) {
            this->handleThreadRestart(workerIndex);
            };

        // Create watchdog with short timeout
        watchdog = std::make_unique<WatchdogWorker>(workers, callback, std::chrono::seconds(1));

        watchdogThread = CreateThread(
            NULL, 0,
            [](LPVOID param) -> DWORD {
                reinterpret_cast<WatchdogWorker*>(param)->start();
                return 0;
            },
            watchdog.get(),
            0, NULL
        );
    }
};

TEST(WorkerManagerTest, WatchdogIntegration) {
    TestWorkerManager manager;
    manager.start(1);

    std::wstring hangFile = L"/System/hang/Data";
    manager.scan(hangFile);

    std::this_thread::sleep_for(std::chrono::seconds(10));

    EXPECT_GT(manager.getWatchdogRestartCount(), 0);

    // Clean up
    manager.stop();
    manager.join();
}