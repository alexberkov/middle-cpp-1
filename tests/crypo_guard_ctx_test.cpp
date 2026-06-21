#include <stdexcept>
#include <ios>
#include <gtest/gtest.h>
#include "crypto_guard_ctx.h"

static constexpr std::string TEST_PASSWORD = "1234";
static constexpr std::string OTHER_PASSWORD = "5678";
static constexpr std::string TEST_INPUT = "This is a test string";

TEST(Crypto, EncryptBadIO) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in}, outStream {std::ios::out};
    inStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD), std::runtime_error);
}

TEST(Crypto, EncryptGoodIO) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in}, outStream {std::ios::out};
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD));
}

TEST(Crypto, DecryptBadIO) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in}, outStream {std::ios::out};
    inStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD), std::runtime_error);
}

TEST(Crypto, DecryptBadFile) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in}, outStream {std::ios::out};

    // EVP error for incorrect block length
    ASSERT_THROW(cryptoCtx.DecryptFile(inStream, outStream, TEST_PASSWORD), std::runtime_error);
}

TEST(Crypto, CorrectEncryption) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in},
            outStream{std::ios::in | std::ios::out}, resStream{std::ios::out};

    cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD);
    cryptoCtx.DecryptFile(outStream, resStream, TEST_PASSWORD);

    ASSERT_STREQ(inStream.str().c_str(), resStream.str().c_str());
}

TEST(Crypto, IncorrectEncryption) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in},
            outStream{std::ios::in | std::ios::out}, resStream{std::ios::out};

    cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD);

    ASSERT_THROW(cryptoCtx.DecryptFile(outStream, resStream, OTHER_PASSWORD), std::runtime_error);
}

TEST(Crypto, ChecksumBadIO) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in};
    inStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.CalculateChecksum(inStream), std::runtime_error);
}

TEST(Crypto, CorrectChecksum) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream{TEST_INPUT, std::ios::in},
            outStream{std::ios::in | std::ios::out}, resStream{std::ios::out};

    cryptoCtx.EncryptFile(inStream, outStream, TEST_PASSWORD);
    cryptoCtx.DecryptFile(outStream, resStream, TEST_PASSWORD);

    std::stringstream initial{inStream.str(), std::ios::in}, processed{resStream.str(), std::ios::in};
    ASSERT_STREQ(cryptoCtx.CalculateChecksum(initial).c_str(), cryptoCtx.CalculateChecksum(processed).c_str());
}
