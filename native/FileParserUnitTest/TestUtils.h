#pragma once
#include <string>
#include <iostream>
#include "CppUnitTest.h"
#include "AVLLib.h"

#include "../Resource/proto/imgDetails.pb.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
#define CREATE_NEW_CATCHFILE 1

class TestUtils {
public:
    static int  value;
    static void print(const std::wstring& message) {
        Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message.c_str());
        std::wcout << message << std::endl;
    }
};
