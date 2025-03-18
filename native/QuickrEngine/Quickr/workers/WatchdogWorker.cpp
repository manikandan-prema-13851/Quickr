#include "WatchdogWorker.h"
#include <iostream>

namespace quickrengine {

    WatchdogWorker::WatchdogWorker(std::vector<std::shared_ptr<Worker>>& workers, std::chrono::seconds timeout)
        : workers(workers), timeout(timeout) {
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
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }

    void WatchdogWorker::checkAndRestartHungWorkers() {
        for (auto& worker : workers) {
            if (worker->isHung(timeout)) {
                std::cerr << "Worker " << worker->getId() << " is hung. Restarting..." << std::endl;
                worker->restart();
                restartCount++;
            }
        }
    }
}