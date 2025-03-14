@echo ON 
set ORIGINAL_PATH=%PATH%
set CDIR=%CD%
set OUTPUT_DIR=%CDIR%\dll_output
set WORK_DIR=%CDIR%
set BUILD_DIR=%WORK_DIR%\FILEPARSER
set SIGN_CAB_DIR="D:\DLL_SETUP\Digital_Signing"

mkdir %OUTPUT_DIR% %BUILD_DIR% %OUTPUT_DIR%\x86 %OUTPUT_DIR%\x64  %OUTPUT_DIR%\include

cd /d %WORK_DIR%

unzip -d FILEPARSER source_fileparser.zip

cd /d %BUILD_DIR%\native\FileParser
xcopy /s /y /d "%BUILD_DIR%\native\FileParser\yara-4.5.1-modified\*" "%BUILD_DIR%\native\FileParser\yara-4.5.1\"

call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

devenv FileParser.sln /clean "Release|x64" /Project .\yara-4.5.1/windows/vs2019/libyara/libyara.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\MalwareClassification\MalClf.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\FileParser\FileParser.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\FileParserExe\FileParserExe.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\FileParserDll\FileParserDll.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\FileParserDllExe\FileParserDllExe.vcxproj

devenv FileParser.sln /clean "Release|x64"  /Project .\FileParserUnitTest\FileParserUnitTest.vcxproj


devenv FileParser.sln /build "Release|x64"  /Project .\yara-4.5.1/windows/vs2019/libyara/libyara.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\MalwareClassification\MalClf.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\FileParser\FileParser.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\FileParserExe\FileParserExe.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\FileParserDll\FileParserDll.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\FileParserDllExe\FileParserDllExe.vcxproj

devenv FileParser.sln /build "Release|x64"  /Project .\FileParserUnitTest\FileParserUnitTest.vcxproj


call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"

devenv FileParser.sln /clean "Release|x86"  /Project .\yara-4.5.1/windows/vs2019/libyara/libyara.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\MalwareClassification\MalClf.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\FileParser\FileParser.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\FileParserExe\FileParserExe.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\FileParserDll\FileParserDll.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\FileParserDllExe\FileParserDllExe.vcxproj

devenv FileParser.sln /clean "Release|x86"  /Project .\FileParserUnitTest\FileParserUnitTest.vcxproj


devenv FileParser.sln /build "Release|x86"  /Project .\yara-4.5.1/windows/vs2019/libyara/libyara.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\MalwareClassification\MalClf.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\FileParser\FileParser.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\FileParserExe\FileParserExe.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\FileParserDll\FileParserDll.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\FileParserDllExe\FileParserDllExe.vcxproj

devenv FileParser.sln /build "Release|x86"  /Project .\FileParserUnitTest\FileParserUnitTest.vcxproj


rem #output copy
cp -Rf %BUILD_DIR%\native\FileParser\FileParser\*.h %OUTPUT_DIR%\include

xcopy /s /y "%BUILD_DIR%\native\FileParser\yara-4.5.1\libyara\include\*.h" "%OUTPUT_DIR%\include"

cp -Rf %BUILD_DIR%\native\FileParser\FeatureExtractor\*.h %OUTPUT_DIR%\include

cp -Rf %BUILD_DIR%\native\FileParser\x64\Release\** %OUTPUT_DIR%\x64

cp -Rf %BUILD_DIR%\native\FileParser\Release\** %OUTPUT_DIR%\x86

cp -Rf %BUILD_DIR%\native\FileParser\Resource\WinTrustedCertificates %OUTPUT_DIR%\x64

cp -Rf %BUILD_DIR%\native\FileParser\Resource\WinTrustedCertificates %OUTPUT_DIR%\x86

cd /d %OUTPUT_DIR%

zip -r file-parse-group-file-sign.zip .

call "%SIGN_CAB_DIR%\signing_build.bat" file-parse-group-file-sign.zip -group-file-sign -specific-host

7z x -y file-parse-group-file-sign.zip

del file-parse-group-file-sign.zip
