#include <gtest/gtest.h>
#include <Quickr/queue/Queue.h>
#include <future>

template <typename T> bool isReady(std::future<T>& future)
{
    return future.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}


struct Task {
    int priority;
    std::string name;

    bool operator<(const Task& other) const {
        return priority < other.priority;
    }
};

TEST(QueueTest, CanPushItemsThenPopThemOut) {
    quickrengine::queue::Queue<Task> pq;

    EXPECT_EQ(pq.size(), 0);
    pq.push({ 1, "Low Priority Task" });
    pq.push({ 3, "High Priority Task" });
    pq.push({ 2, "Medium Priority Task" });

    EXPECT_EQ(pq.size(), 3); 


    auto task = pq.front();
    EXPECT_EQ(task.name, "High Priority Task");
    EXPECT_EQ(pq.size(), 2); 

    task = pq.front();
    EXPECT_EQ(task.name, "Medium Priority Task");
    EXPECT_EQ(pq.size(), 1); 

    task = pq.front();
    EXPECT_EQ(task.name, "Low Priority Task");
    EXPECT_EQ(pq.size(), 0); 
}

TEST(QueueTest, CanWaitUntilItemsAreAdded) {
    quickrengine::queue::Queue<Task> pq;

    EXPECT_EQ(pq.size(), 0);
    pq.push({ 3, "High Priority Task" });
    pq.push({ 2, "Medium Priority Task" });
    {
        auto future1 = std::async([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto f = pq.front();
            return f;
            });

        auto future2 = std::async([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            auto f = pq.front();
            return f;
            });

        auto future3 = std::async([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            auto f = pq.front();
            return f;
            });

        std::this_thread::sleep_for(std::chrono::milliseconds(210));

        EXPECT_EQ(future1.get().name , "High Priority Task");
        EXPECT_EQ(future2.get().name, "Medium Priority Task");


        EXPECT_EQ(pq.size(), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        EXPECT_FALSE(isReady(future3));

        pq.push({ 4, "Highest Priority Task" });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        EXPECT_EQ(pq.size() , 0);
        EXPECT_TRUE(isReady(future3));
        EXPECT_EQ(future3.get().name, "Highest Priority Task");
    }

}

