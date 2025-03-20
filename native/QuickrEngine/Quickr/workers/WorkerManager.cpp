#include "WorkerManager.h"
#include <iostream>
#include <cassert>
#include "../QuickrEngine/quickengine_version.h"
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

	DWORD WINAPI WorkerThreadStart(LPVOID lpParam) {
		Worker* worker = static_cast<Worker*>(lpParam);
		worker->start();
		return 0;
	}

	HANDLE WorkerManager::createWorkerThread(int index) {
		assert(fileWorkQueue != nullptr);
		assert(resultQueue != nullptr);

		auto worker = std::make_shared<Worker>(fileWorkQueue, resultQueue, index);
		workers.insert(workers.begin() + index, worker);
		HANDLE threadHandle = CreateThread(
			NULL,            // Default security attributes
			0,               // Default stack size
			WorkerThreadStart, // Function to execute
			worker.get(),    // Thread function argument
			0,               // Run immediately
			NULL             // Don't need thread ID
		);

		return threadHandle;
	}

	void WorkerManager::start(unsigned int wantedWorkers) {
		stop();

		for (unsigned int i = 0; i < wantedWorkers; i++) {

			HANDLE threadHandle = createWorkerThread(i);

			if (threadHandle) {
				workerThreads.push_back(threadHandle);
			}
			else {
				std::cerr << "Failed to create worker thread!\n";
			}
		}

		// Watchdog initialization
		ThreadRestartCallback callback = [this](int workerIndex) {
			this->handleThreadRestart(workerIndex);
			};

		watchdog = std::make_unique<WatchdogWorker>(workers, callback, workerTimeout);

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
		if (watchdogThread) {
			WaitForSingleObject(watchdogThread, INFINITE);
			CloseHandle(watchdogThread);
			watchdogThread = NULL;
		}

		// Join worker threads
		for (HANDLE threadHandle : workerThreads) {
			if (threadHandle) {
				WaitForSingleObject(threadHandle, INFINITE);
				CloseHandle(threadHandle);
			}
		}
		workerThreads.clear();
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

	void WorkerManager::handleThreadRestart(int workerIndex) {
		std::lock_guard<std::mutex> lock(threadMutex);
		if (workerIndex < 0 || workerIndex >= workerThreads.size()) {
			return;
		}

		if (workerThreads[workerIndex]) {
			DEBUG_MSG("Number of thrad running before kill a thread " << workerThreads.size());


			// Forcefully terminate the thread if needed
			if (!TerminateThread(workerThreads[workerIndex], 1)) {
				DEFAULT_MSG ("Failed to terminate thread: " << workerIndex );
			}
			CloseHandle(workerThreads[workerIndex]);



			workers.erase(workers.begin() + workerIndex);
			workerThreads.erase(workerThreads.begin() + workerIndex);
			DEBUG_MSG("Number of thrad running after kill a thread " << workerThreads.size());
		}
		HANDLE threadHandle = createWorkerThread(workerIndex);
		// Replace with the new thread
		workerThreads.push_back(threadHandle);
	}

}