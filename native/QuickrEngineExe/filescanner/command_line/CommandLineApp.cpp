



#include "CommandLineApp.h"
#include "CommandLineOptions.h"


void printHelp() {
    std::cout << "Usage: program [options] [input-file...]\n";
    std::cout << "Options:\n";
    std::cout << "  --help                \tPrint this help message\n";
    std::cout << "  --debug               \tEnable debug logging\n";
    std::cout << "  --trace               \tEnable trace logging\n";
    std::cout << "  --server              \tStay running as HTTP server\n";
    std::cout << "  --num-workers <num>   \tThe number of worker threads to use\n";
    std::cout << "  --categories          \tList existing file categories\n";
    std::cout << "  --category-find <name>\tList entries of a certain category\n";
}
namespace quickrmc::command_line {
    int CommandLineApp::main(int argc, wchar_t** argv) const {
        const auto commandLineOptions = CommandLineOptions::fromArgs(argc, argv);
        if (commandLineOptions.getCommandType() == CommandType::HELP_COMMANDTYPE) {
            printHelp();
            return 0;
        }

        if (commandLineOptions.getCommandType() == CommandType::AGENT_FLOW) {
            const auto scanCommandOptions = std::get<ScanCommandOptions>(commandLineOptions.getDetailOptions());
            return handleAgentFlow(scanCommandOptions);
        }
    }

    bool CommandLineApp::handleAgentFlow(ScanCommandOptions scanCommandOptions) const {
        std::wcout << L"Handle Agent FLow Scan " << std::endl;
        static FileSaverFactory fileSaverFactory;
        auto& fileSaver = fileSaverFactory.getRef();

        if (scanCommandOptions.numWorkers != 0)
        {
            fileSaver.setNumWorkers(scanCommandOptions.numWorkers);
        }
        const auto startTime = std::chrono::steady_clock::now();
        fileSaver.start();

        //std::unique_ptr<QuickrMc> mcEngine = 
        return 0;
    }
}




