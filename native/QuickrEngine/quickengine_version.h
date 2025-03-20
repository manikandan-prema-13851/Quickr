#pragma once
#define WATCH_DOG_PERIODIC_TIME_IN_SEC 1

#define DEV_MODE 
#ifdef DEV_MODE
	#define TEST_MODE
	#define DEBUG 1
#endif

#if DEBUG
#define DEBUG_MSG(x) std::wcout << "[" << (__FILE__) << ":" << __LINE__ << "] " << x << std::endl;
//std::cout << "Debug: " << x << std::endl;
#else
#define DEBUG_MSG(x)
#endif
#define DEFAULT_MSG(x) std::wcout << L"[" << (__FILE__) << L":" << __LINE__ << L"] " << x << std::endl;
