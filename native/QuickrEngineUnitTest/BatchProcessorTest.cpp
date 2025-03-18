#include <gtest/gtest.h>
#include <fstream>
#include <chrono>
#include "TestUtils.h"
#include <Quickr/queue/Queue.h>
#include <Quickr/models/FileMeta.h>
#include <Quickr/services/BatchProcessor/BatchProcessor.h>
#include <Quickr/workers/Worker.h>
#include <iostream>

TEST(AggregationWorker, Init) {
    using quickrengine::FileMeta;
    using quickrengine::Worker;
    using quickrengine::queue::Queue;
    using std::shared_ptr;
    using quickrengine::services::BatchProcessor;

    auto workQueue = std::make_shared<Queue<std::wstring>>();
    auto resultQueue = std::make_shared<Queue<shared_ptr<FileMeta>>>();
    long long id = 0;
    Worker worker{ workQueue, resultQueue, id };
    BatchProcessor rWorker{ resultQueue };

    auto tmpDir = quickrengine::test::GetTempDirectoryPath();
    tmpDir = tmpDir + L"filesaver_worker_test_" + std::to_wstring(std::chrono::system_clock::now().time_since_epoch().count());

    auto randomFilePath = tmpDir;

    quickrengine::test::removeDirectory(tmpDir);
    EXPECT_TRUE(quickrengine::test::createDirectory(tmpDir));

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

    EXPECT_EQ(workQueue->size(), 0);
    EXPECT_EQ(resultQueue->size(), 0);

    worker.processEntry(tmpDir);

    EXPECT_TRUE(resultQueue->size() == 1);
    EXPECT_TRUE(workQueue->size() == 2);


    rWorker.run();
    quickrengine::test::removeDirectory(tmpDir);

}

