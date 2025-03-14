#include <gtest/gtest.h>
#include <fstream>
#include <chrono>
#include "TestUtils.h"
#include <Quickr/queue/Queue.h>
#include <Quickr/models/FileMeta.h>
#include <Quickr/workers/Worker.h>


TEST(Worker, Init) {
    using quickrengine::FileMeta;
    using quickrengine::Worker;
    using quickrengine::queue::Queue;

    using std::shared_ptr;

    auto workQueue = std::make_shared<Queue<std::wstring>>();
    auto resultQueue = std::make_shared<Queue<shared_ptr<FileMeta>>>();
    long long id = 0;
   
    Worker worker{ workQueue, resultQueue, id };
    std::thread workerThread{ &Worker::start, &worker };


    auto tmpDir = quickrmc::test::GetTempDirectoryPath();
    auto randomFilePath = tmpDir;

    randomFilePath.append(L"random-file");
    {
        std::ofstream outputStream{ randomFilePath.c_str()};
        outputStream << "hello";
    }
    workQueue->push(randomFilePath);

    auto result = resultQueue->frontWithTimeout(std::chrono::milliseconds(10000));
    EXPECT_TRUE(result.has_value());
    auto entry = result.value();
    EXPECT_EQ(entry->filepath, randomFilePath.c_str());
    EXPECT_TRUE(entry->size == 5);
    EXPECT_TRUE(entry->type == quickrengine::FileType::regular_file);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    worker.stop();
    workerThread.join();

}


TEST(Worker, processEntry) {
    using quickrengine::FileMeta;
    using quickrengine::Worker;
    using quickrengine::queue::Queue;
    using std::shared_ptr;


    auto workQueue = std::make_shared<Queue<std::wstring>>();
    auto resultQueue = std::make_shared<Queue<shared_ptr<FileMeta>>>();
    long long id = 0;
    Worker worker{ workQueue, resultQueue, id};


    auto tmpDir = quickrmc::test::GetTempDirectoryPath();
    tmpDir = tmpDir + L"filesaver_worker_test_" +  std::to_wstring(std::chrono::system_clock::now().time_since_epoch().count());

    auto randomFilePath = tmpDir;

    quickrmc::test::removeDirectory(tmpDir);
    assert(quickrmc::test::createDirectory(tmpDir));

    std::wstring randomFilePath1 = tmpDir + L"\\random-file1.txt";
    std::wstring randomFilePath2 = tmpDir + L"\\random-file2.txt";

    {
        std::ofstream outputStream(randomFilePath1);
        outputStream << "hello";
    }
    {
        std::ofstream outputStream(randomFilePath2);
        outputStream << "hello";
    }

    EXPECT_EQ(workQueue->size() , 0);
    EXPECT_EQ(resultQueue->size() , 0);

    worker.processEntry(tmpDir);

    EXPECT_TRUE(resultQueue->size() == 1);
    EXPECT_TRUE(workQueue->size() == 2);

    quickrmc::test::removeDirectory(tmpDir);
}
