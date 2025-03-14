#include "ThreadTimer.h"
namespace quickrengine
{

    void ThreadTimer::start()
    {
        startTime = std::chrono::steady_clock::now();
    }

    void ThreadTimer::stop()
    {
        if (!startTime.has_value())
        {
            return;
        }

        auto now = std::chrono::steady_clock::now();
        totalElapsed += std::chrono::duration_cast<std::chrono::milliseconds> (now - startTime.value()).count();
        startTime = std::optional<std::chrono::time_point<std::chrono::steady_clock>>();
    }

    long long int ThreadTimer::getElapsedMilliseconds() const
    {
        if (startTime.has_value())
        {
            auto now = std::chrono::steady_clock::now();
            auto currentElapsed = std::chrono::duration_cast<std::chrono::milliseconds> (now - startTime.value()).count();
            return totalElapsed + currentElapsed;
        }

        return totalElapsed;
    }

}