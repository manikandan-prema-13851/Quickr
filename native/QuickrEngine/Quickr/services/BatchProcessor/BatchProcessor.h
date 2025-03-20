
#ifndef QUICKR_MC_AGGREGATIONWORKER_H
#define QUICKR_MC_AGGREGATIONWORKER_H

#include <memory>
#include <vector>

#include "../../models/FileMeta.h"
#include "../../queue/Queue.h"
namespace quickrengine::services {

	class BatchProcessor {
	public:
		BatchProcessor(std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> queue);

		~BatchProcessor()
		{
		};
		void stop();
		void run();

	private:
		std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> resultQueue{ nullptr };
		bool running = false;

	};

}

#endif



