#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>
#include <fstream>

std::fstream get_filestream(const std::string& filename, std::ios::openmode mode) {
    std::fstream fs;
    fs.open(filename, mode);
    if (!fs.is_open())
        throw std::invalid_argument("Incorrect filepath.");
    return fs;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
            case COMMAND_TYPE::ENCRYPT: {
                auto input_file = get_filestream(options.GetInputFile(), std::ios::in),
                        output_file = get_filestream(options.GetOutputFile(), std::ios::out);
                cryptoCtx.EncryptFile(input_file, output_file, options.GetPassword());
                std::print("File encoded successfully\n");
                break;
            }
            case COMMAND_TYPE::DECRYPT: {
                auto input_file = get_filestream(options.GetInputFile(), std::ios::in),
                        output_file = get_filestream(options.GetOutputFile(), std::ios::out);
                cryptoCtx.DecryptFile(input_file, output_file, options.GetPassword());
                std::print("File decoded successfully\n");
                break;
            }
            case COMMAND_TYPE::CHECKSUM: {
                auto input_file = get_filestream(options.GetInputFile(), std::ios::in);
                std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(input_file));
                break;
            }
            default:
                throw std::runtime_error{"Unsupported command"};
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }
    return 0;
}