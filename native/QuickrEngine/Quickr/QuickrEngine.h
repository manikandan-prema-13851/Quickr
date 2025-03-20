#pragma once
#include <iostream>
#include "thread_timer/ThreadTimer.h"
#include "workers/WorkerManager.h"
#include "services/BatchProcessor/BatchProcessor.h"
#include "scanner/PEScanner.h"




#define MODEL_VERSION L"1" 
namespace quickrengine {
class QuickrEngine {
public:
	QuickrEngine(); 
	~QuickrEngine();
	void start(wchar_t*,int);
	void stop();
	static void join();

	void scan(const std::wstring filepath);

	static std::wstring getVersion();

private:
	std::atomic<unsigned int> numWorkers = 0;
	std::atomic<bool> running = false;
	ThreadTimer timer;
	WorkerManager manager;
	PEScanner* peScanner;

	services::BatchProcessor batchProcessorWorker;
};
}
