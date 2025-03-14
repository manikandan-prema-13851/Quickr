//
// Created by Pedro Tacla Yamada on 29/4/21.
//

#ifndef FILESAVER_COMMANDLINEOPTIONS_H
#define FILESAVER_COMMANDLINEOPTIONS_H
#include "../../lfilesaver/FileSaver.h"
#include <string>
#include <vector>
#include <variant>
namespace quickrmc::command_line
{
	enum class LogLevel
	{
		TRACE,
		DEBUG,
		INFO,
	};

	enum class CommandType
	{
		HELP_COMMANDTYPE,
		AGENT_FLOW,
		SCAN_COMMAND,
		LIST_CATEGORIES,
		CATEGORY_FIND,
	};

	struct EmptyOptions {};

	struct ScanCommandOptions
	{
		std::vector<std::string> inputFiles{};
		unsigned int numWorkers = 0;
		bool server = false;
	};

	struct CategoryFindOptions
	{
		std::string categoryName;
	};

	using DetailOptions = std::variant<EmptyOptions, ScanCommandOptions, CategoryFindOptions>;

	class CommandLineOptions
	{
	public:
		static CommandLineOptions fromArgs(int argc, wchar_t** argv);
		LogLevel getLogLevel() const;
		CommandType getCommandType() const;
		const DetailOptions& getDetailOptions() const;
		const std::string& getPublicDescription() const;
		void printCommandLineOptions() const;

	private:
		CommandLineOptions() = default;

		std::string m_publicDescription = "General options";

		// General options
		LogLevel m_logLevel = LogLevel::INFO;

		// Command types and command specific options
		CommandType m_commandType = CommandType::HELP_COMMANDTYPE;
		DetailOptions m_detailOptions = EmptyOptions{};
	};

}
#endif // FILESAVER_COMMANDLINEOPTIONS_H
