#include <chrono>
#include <optional>

namespace quickrengine {
	class ThreadTimer {
	public:
		ThreadTimer() = default;

        void start();

        void stop();

        long long int getElapsedMilliseconds() const;

	private:
		std::optional<std::chrono::time_point<std::chrono::steady_clock>> startTime = {};
		long long int totalElapsed = 0;
	};
}