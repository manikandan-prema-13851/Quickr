#ifndef QUICKR_MC_WORKER_H
#define QUICKR_MC_WORKER_H


#include <iostream>
#include <string>

#include "../queue/Queue.h"
#include "../models/FileMeta.h"


namespace quickrengine {
	class Worker {
	public:
		Worker(std::shared_ptr<queue::Queue<std::wstring>> queue, std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> rqueue, long long id);

		void start();
		void stop();
		void processEntry(std::wstring& file);
		unsigned long getFilesProcessed();

	private:
		bool running = false;
		unsigned long filesProcessed = 0;

		long long running_id = 0;

		std::shared_ptr<queue::Queue<std::wstring>> workQueue{ nullptr };
		std::shared_ptr<queue::Queue<std::shared_ptr<quickrengine::FileMeta>>> resultQueue{ nullptr };

   };
}

#endif

