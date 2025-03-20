#ifndef QUICKR_MC_WATCHDOG_WORKER_H
#define QUICKR_MC_WATCHDOG_WORKER_H

#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <functional>
#include "Worker.h"

namespace quickrengine {
    using ThreadRestartCallback = std::function<void(int)>;


    class WatchdogWorker {
    public:
        WatchdogWorker(std::vector<std::shared_ptr<Worker>>& workers,
            ThreadRestartCallback restartCallback,
            std::chrono::seconds timeout = std::chrono::seconds(30));

        void start();
        void stop();

        // For testing purposes
        size_t getRestartCount() const;

    private:
        std::vector<std::shared_ptr<Worker>>& workers;
        ThreadRestartCallback restartCallback;
        std::chrono::seconds timeout;
        std::atomic<bool> running{ false };
        std::atomic<size_t> restartCount{ 0 };

        void watchLoop();
        void checkAndRestartHungWorkers();
    };
}

#endif