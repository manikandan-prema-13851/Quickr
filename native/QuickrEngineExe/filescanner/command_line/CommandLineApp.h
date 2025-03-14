



#ifndef FILE_SAVER_COMMANDLINEAPP_H
#define FILE_SAVER_COMMANDLINEAPP_H



#include <chrono>
#include "GenericLogger.h"

#include "../lfilesaver/FileSaver.h"
#include"../lfilesaver/factory/FileSaverFactory.h"

#include "CommandLineOptions.h"


#define CLI_LOG_DELAY 300


namespace quickrmc::command_line {




















    class CommandLineApp
    {
    public:
        int main(int argc, wchar_t** argv) const;

    private:
        bool handleAgentFlow(ScanCommandOptions) const;

    };
}


#endif // FILE_SAVER_COMMANDLINEAPP_H