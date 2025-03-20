#include "WatchdogWorker.h"
#include "../QuickrEngine/quickengine_version.h"
#include <iostream>

namespace quickrengine {

    WatchdogWorker::WatchdogWorker(std::vector<std::shared_ptr<Worker>>& workers,
        ThreadRestartCallback restartCallback,
        std::chrono::seconds timeout)
        : workers(workers), restartCallback(restartCallback), timeout(timeout) {
    }

    void WatchdogWorker::start() {
        running = true;
        watchLoop();
    }

    void WatchdogWorker::stop() {
        running = false;
    }

    size_t WatchdogWorker::getRestartCount() const {
        return restartCount;
    }

    void WatchdogWorker::watchLoop() {
        while (running) {
            checkAndRestartHungWorkers();
            // Check every 15 second for hung workers
            std::this_thread::sleep_for(std::chrono::seconds(WATCH_DOG_PERIODIC_TIME_IN_SEC));
        }
        DEBUG_MSG(L"Watchdog stopped.");
    }

    void WatchdogWorker::checkAndRestartHungWorkers() {
        for (int i = 0; i < workers.size(); i++) {
            auto& worker = workers[i];
            if (worker->isHung(timeout)) {
                DEFAULT_MSG (L"Worker " << worker->getId() << L" is hung. Killing and restarting thread...");
                // Stop the worker
                worker->stop();

                // Mark the task as complete
                worker->restart();

                if (restartCallback) {
                    restartCallback(i);
                }
                restartCount++;
            }
        }
    }

}