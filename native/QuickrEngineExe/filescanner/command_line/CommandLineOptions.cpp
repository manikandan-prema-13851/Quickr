#include "CommandLineOptions.h"

namespace quickrmc::command_line{
CommandLineOptions CommandLineOptions::fromArgs(int argc, wchar_t** argv) {
    CommandLineOptions options;

    std::vector<std::wstring> args(argv, argv + argc);
    std::vector<std::string> inputFiles;
    unsigned int numWorkers = 0;
    std::string lsCategoryName;
    bool server = false;

    for (size_t i = 1; i < args.size(); ++i) {
        std::wstring arg = args[i];

        // Handle flags
        if (arg == L"--help") {
            options.m_commandType = CommandType::HELP_COMMANDTYPE;
            return options;
        }
        else if (arg == L"--debug") {
            options.m_logLevel = LogLevel::DEBUG;
        }
        else if (arg == L"--trace") {
            options.m_logLevel = LogLevel::TRACE;
        }
        else if (arg == L"--server") {
            server = true;
        }
        else if (arg == L"--categories") {
            options.m_commandType = CommandType::LIST_CATEGORIES;
            return options;
        }
        // Handle options with values
        else if (arg == L"--num-workers" && i + 1 < args.size()) {
            numWorkers = std::stoul(args[++i]);
        }
        else if (arg == L"--ondemandscan" && i + 1 < args.size()) {
            lsCategoryName = std::string(args[++i].begin(), args[i].end());
            options.m_commandType = CommandType::CATEGORY_FIND;
            CategoryFindOptions categoryFindOptions;
            categoryFindOptions.categoryName = lsCategoryName;
            options.m_detailOptions = categoryFindOptions;
            return options;
        }
        // Handle positional arguments (input files)
        else {
            inputFiles.push_back(std::string(arg.begin(), arg.end()));
        }
    }

    // Default to scan command
    options.m_commandType = CommandType::AGENT_FLOW;
    ScanCommandOptions scanCommandOptions;
    scanCommandOptions.inputFiles = inputFiles;
    scanCommandOptions.numWorkers = numWorkers;
    scanCommandOptions.server = server;
    options.m_detailOptions = scanCommandOptions;

    return options;
}
LogLevel CommandLineOptions::getLogLevel() const
{
    return m_logLevel;
}

CommandType CommandLineOptions::getCommandType() const
{
    return m_commandType;
}

const DetailOptions& CommandLineOptions::getDetailOptions() const
{
    return m_detailOptions;
}

const std::string& CommandLineOptions::getPublicDescription() const
{
    return m_publicDescription;
}

void CommandLineOptions::printCommandLineOptions() const { 
}
}