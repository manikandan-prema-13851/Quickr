

#include "BatchProcessor.h"
#include "../QuickrEngine/quickengine_version.h"
#include <fstream>

namespace quickrengine {

	namespace services {

		BatchProcessor::BatchProcessor(const std::shared_ptr<queue::Queue<std::shared_ptr<FileMeta>>> queue) :resultQueue(queue), running(true) {
		}

		void BatchProcessor::stop() {
			running = false;
		}

		void BatchProcessor::run() {

			FILE* fptr = nullptr;
			errno_t err = _wfopen_s(&fptr, L"d:\\output.txt", L"w");

			int count = 0;

			if (err != 0 || fptr == nullptr) {
				std::wcerr << L"Failed to open file: " << L"output.txt" << std::endl;
			}

			while (running) {
				auto fileData = resultQueue->frontWithTimeout(std::chrono::milliseconds(10));
				if (fileData.has_value()) {
					auto fileEntry = fileData.value();
					if (fptr) {
						fwprintf(fptr, L"%s", fileEntry->filepath.c_str());
						fwprintf(fptr, L",%ld", fileEntry->size);
						fwprintf(fptr, L",%ld", fileEntry->type);
						fwprintf(fptr, L",%lld", fileEntry->currentmillisec);
						fwprintf(fptr, L",%lld\n", fileEntry->threadId);
						count++;
					}
				}
				else {
					running = false;
				}
			}

			if (fptr) {
				fclose(fptr);
			}

			DEBUG_MSG("Total Files: " << count);
		}

	}

}
