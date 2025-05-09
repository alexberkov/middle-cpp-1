#include <vector>
#include <stdexcept>
#include <gtest/gtest.h>
#include "cmd_options.h"

class CommandLineArgs {
public:
    CommandLineArgs(std::initializer_list<const char*> args_): args{args_} {}
    size_t argc() const { return args.size(); }
    char** argv() const { return const_cast<char**>(args.data()); }
private:
    std::vector<const char*> args;
};

TEST(Commands, HelpCommand) {
    CommandLineArgs cmdline{"CryptoGuard", "--help"};
    CryptoGuard::ProgramOptions options;
    ASSERT_NO_THROW(options.Parse(cmdline.argc(), cmdline.argv()));
}

TEST(Commands, EncryptCommand) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt", "-o", "encrypted.txt", "-p", "1234", "--command", "encrypt"};
    CryptoGuard::ProgramOptions options;
    ASSERT_NO_THROW(options.Parse(cmdline.argc(), cmdline.argv()));
    ASSERT_STREQ(options.GetInputFile().c_str(), "input.txt");
    ASSERT_STREQ(options.GetOutputFile().c_str(), "encrypted.txt");
    ASSERT_STREQ(options.GetPassword().c_str(), "1234");
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(Commands, ChecksumCommand) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt", "--command", "checksum"};
    CryptoGuard::ProgramOptions options;
    ASSERT_NO_THROW(options.Parse(cmdline.argc(), cmdline.argv()));
    ASSERT_STREQ(options.GetInputFile().c_str(), "input.txt");
    ASSERT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(Commands, NoCommand) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt"};
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(cmdline.argc(), cmdline.argv()), std::runtime_error);
}

TEST(Commands, IncorrectCommand) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt", "--command", "unknown"};
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(cmdline.argc(), cmdline.argv()), std::runtime_error);
}

TEST(Commands, NoInputFile) {
    CommandLineArgs cmdline{"CryptoGuard", "--command", "checksum"};
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(cmdline.argc(), cmdline.argv()), std::runtime_error);
}

TEST(Commands, NoOutputFile) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt", "-p", "1234", "--command", "encrypt"};
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(cmdline.argc(), cmdline.argv()), std::runtime_error);
}

TEST(Commands, NoPassword) {
    CommandLineArgs cmdline{"CryptoGuard", "-i", "input.txt", "-o", "encrypted.txt", "--command", "encrypt"};
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(cmdline.argc(), cmdline.argv()), std::runtime_error);
}