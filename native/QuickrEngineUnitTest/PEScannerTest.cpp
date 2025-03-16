#include <Quickr/scanner/PEScanner.h>
#include <gtest/gtest.h>

// Test fixture for PEScanner
class PEScannerTest : public ::testing::Test {
protected:
    quickrengine::PEScanner* scanner = NULL;

    virtual void SetUp() {
        scanner = quickrengine::PEScanner::getInstance();
    }

    virtual void TearDown() {
        scanner = nullptr;
    }
    wchar_t* yaraRulePath = (wchar_t*)L"d:\\yara.yar";
	wchar_t* validPEFilePath = (wchar_t*)L"C:\\windows\\notepad.exe";
};

TEST_F(PEScannerTest, InitPEScannerValidPath) {
    bool result = scanner->initPEScanner(yaraRulePath);
    EXPECT_TRUE(result) << "Failed to initialize PEScanner with a valid YARA rule path.";
}

TEST_F(PEScannerTest, CheckReadyState) {
    scanner->initPEScanner(yaraRulePath);
    bool isReady = scanner->isReadyState();
    ASSERT_TRUE(isReady) << "PEScanner is not in ready state after initialization with a valid YARA rule path.";

    wchar_t invalidYaraRulePath[] = L"invalid_path/yara_rules.yar";
    bool result = scanner->initPEScanner(invalidYaraRulePath);
    ASSERT_FALSE(result) << "Initialized PEScanner with an invalid YARA rule path, which should not happen.";

    scanner->initPEScanner(yaraRulePath);
    isReady = scanner->isReadyState();
    ASSERT_TRUE(isReady) << "PEScanner is not in ready state after initialization with a valid YARA rule path.";
}

TEST_F(PEScannerTest, InitPEScannerInvalidPath) {
    wchar_t invalidYaraRulePath[] = L"invalid_path/yara_rules.yar";
    bool result = scanner->initPEScanner(invalidYaraRulePath);
    ASSERT_FALSE(result) << "Initialized PEScanner with an invalid YARA rule path, which should not happen.";
}

TEST_F(PEScannerTest, ScanValidPEFile) {
    ScannerConfig config;
    PEImgDetails* result = scanner->PEScanFile(validPEFilePath, &config);
    ASSERT_NE(result, nullptr) << "Failed to scan a valid PE file.";
    scanner->freePEData(result);
}

TEST_F(PEScannerTest, ScanInvalidPEFile) {
    wchar_t invalidPEFilePath[] = L"path/to/invalid/pefile.exe";
    ScannerConfig config;
    PEImgDetails* result = scanner->PEScanFile(invalidPEFilePath, &config);

    ASSERT_EQ(result, nullptr) << "Scanned an invalid PE file successfully, which should not happen.";
}

// Test case for scanning a non-existent file
TEST_F(PEScannerTest, ScanNonExistentFile) {
    wchar_t nonExistentFilePath[] = L"path/to/nonexistent/file.exe";
    ScannerConfig config;
    PEImgDetails* result = scanner->PEScanFile(nonExistentFilePath, &config);

    ASSERT_EQ(result, nullptr) << "Scanned a non-existent file successfully, which should not happen.";
}

// Main function to run all tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}