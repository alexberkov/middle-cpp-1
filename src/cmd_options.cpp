#include <iostream>
#include "cmd_options.h"

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "show allowed options")
            ("command,c", po::value(&command_str_)->value_name("encrypt/decrypt/checksum")->required(),
                "action to perform")
            ("input,i", po::value(&inputFile_)->value_name("filename")->required(),
                "set input file path")
            ("output,o", po::value(&outputFile_)->value_name("filename"),
                "set output file path")
            ("password,p", po::value(&password_)->value_name("string"),
                "set password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        std::cout << desc_;
        return;
    }

    if (const auto it = commandMapping_.find(command_str_); it != commandMapping_.end())
        command_ = it->second;
    else
        throw std::runtime_error(std::format("Unknown command: {}", command_str_));

    if (command_ != COMMAND_TYPE::CHECKSUM) {
        if (!vm.contains("output"))
            throw std::runtime_error("Output file is not specified.");

        if (!vm.contains("password"))
            throw std::runtime_error("Password is not specified.");
    }
}

}  // namespace CryptoGuard
