#ifndef QUICKR_MC_WORKQUEUE_H
#define QUICKR_MC_WORKQUEUE_H
#include <condition_variable>
#include <optional>
#include <queue>
#include<cassert>

namespace quickrengine {

	namespace queue
	{

		/// Provides a lock based priority queue
		/**
		 * This is a simple lock based priority  queue.
		 */

		template <typename T, typename Compare = std::less<T>> // Default to max - heap(largest element on top)
		class Queue
		{
		public:
			/**
			 * Try to pop an element from the queue, waiting for `timeout` milliseconds
			 * for it to be available.
			 *
			 * @param timeout Amount of time to wait for an element to be available.
			 * @return Maybe an element
			 */
			std::optional<T> frontWithTimeout(std::chrono::milliseconds timeout)
			{
				std::unique_lock lock(criticalSection);

				while (store.empty())
				{
					auto hasValue = conditionVariable.wait_for(lock, timeout, [&] { return !store.empty(); });

					if (!hasValue)
					{
						return std::nullopt;
					}
				}

				assert(lock.owns_lock());
				assert(!store.empty());

				auto element = store.top();
				store.pop();

				return { std::move(element) };
			}

			/**
			 * Pop an element from the queue, waiting for until an element is available
			 * if it's empty.
			 */
			T front()
			{
				std::unique_lock lock(criticalSection);

				while (store.empty())
				{
					conditionVariable.wait(lock, [&] { return !store.empty(); });
				}

				assert(lock.owns_lock());
				assert(!store.empty());

				auto element = store.top();
				store.pop();

				return element;
			}

			/**
			 * Push an element into the queue.
			 */
			void push(const T& item)
			{
				std::lock_guard lock(criticalSection);
				store.push(item);
				conditionVariable.notify_all();
			}

			/**
			 * Move an element into the queue.
			 */
			void push(T&& item)
			{
				std::lock_guard lock(criticalSection);
				store.push(item);
				conditionVariable.notify_all();
			}

			/**
			 * Get the queue size.
			 */
			size_t size()
			{
				std::lock_guard lock(criticalSection);
				return store.size();
			}

		private:
			std::priority_queue<T, std::vector<T>, Compare> store{};
			std::mutex criticalSection{};
			std::condition_variable conditionVariable{};
		};

	} // namespace data

}

#endif