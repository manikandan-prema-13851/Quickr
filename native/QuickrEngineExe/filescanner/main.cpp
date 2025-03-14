#include "command_line/CommandLineApp.h"

int wmain(int argc, wchar_t* argv[]) {
	quickrmc::command_line::CommandLineApp commandLineApp{};
	return commandLineApp.main(argc, argv);
}