#include <iostream>
#include <windows.h>
#include <Quickr/QuickrEngine.h>
#include <chrono>


/*
    quickrengine 
*/

int wmain() {

    int i = 0;

    //while (i <= 3) {
        quickrengine::QuickrEngine s; // its just init and need to load after create opject
        wchar_t* patternPath = (wchar_t*)L"D:\\yara.yar";
        
        int numWorkers = std::thread::hardware_concurrency() * 2;
        numWorkers = 1;
        s.start(patternPath,numWorkers);


        auto start = std::chrono::high_resolution_clock::now();

        s.scan(L"D:\\dataset\\AVC_Sampleshare_Client");

        auto end = std::chrono::high_resolution_clock::now();

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        auto duration_sec = std::chrono::duration<double>(end - start).count();

        std::wcout << L"Scan completed in " << duration_ms.count() << L" milliseconds ("
            << duration_sec << L" seconds)." << std::endl;

        s.stop();
        i++;
    //}
    
    return 0;
}
