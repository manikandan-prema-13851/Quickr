#include <thread>
#include "QuickrEngine.h"
#include "..\quickengine_version.h"

namespace quickrengine {
	QuickrEngine::QuickrEngine() : batchProcessorWorker(manager.getResultQueue()) {
		peScanner = peScanner->getInstance();
	}
	QuickrEngine::~QuickrEngine() {
		DEBUG_MSG("QuickrEngine::stop");
		stop();
	}
	void QuickrEngine::stop() {
		manager.stop();
	}
	void QuickrEngine::start(wchar_t* patternPath, int _numWorkers) {
		numWorkers = _numWorkers;
		DEBUG_MSG(L"QuickrEngine::start numofthreads:: " << numWorkers);
		timer.start();
		manager.stop();
		peScanner->initPEScanner(patternPath);
		manager.start(numWorkers);
		running = true;
	}

	void QuickrEngine::join() {
	
	}
	
	void QuickrEngine::scan(const std::wstring filepath) {
		DEBUG_MSG("scanning started:: ");
		DEBUG_MSG(filepath);
		manager.scan(filepath);
		batchProcessorWorker.run();
	}

	std::wstring QuickrEngine::getVersion()
	{
#ifdef MODEL_VERSION
		std::wstring result{ MODEL_VERSION };
		if (result.empty())
		{
			return L"unknown";
		}
		return result;
#else
		return L"unknown";
#endif
	}

}