@echo ON 
set CDIR=%CD%
set ORIGINAL_PATH=%PATH%


cd /d %CDIR%\native\FileParser\

devenv FileParser.sln /Rebuild "Release|x64"  /Project .\FileParserUnitTest/FileParserUnitTest.vcxproj


:: Navigate to the output directory (assuming Release/x64 output path)
cd /d %CDIR%\native\FileParser\x64\Release\

:: Run the built executable
vstest.console.exe FileParserUnitTest.dll

cd /d %CDIR%