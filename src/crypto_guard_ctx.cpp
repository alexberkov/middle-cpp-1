#include <memory>
#include <vector>
#include <array>
#include <format>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto_guard_ctx.h"

static constexpr size_t MAX_ERR_SIZE = 256;
static constexpr size_t BLOCK_LEN = 1024;
static constexpr std::string MD_ALGO = "sha256";

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

namespace CryptoGuard {

struct CipherCTXDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

struct MDCTXDeleter {
    void operator()(EVP_MD_CTX *ctx) const { EVP_MD_CTX_free(ctx); }
};

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    void InitCipherCTX(std::string_view password, int encrypt);
    void InitMDCTX();

    void ProcessFile(std::iostream &inStream, std::iostream &outStream);
    std::string CalculateChecksum(std::iostream &inStream);

    void ThrowEVPError();
private:
    std::unique_ptr<EVP_CIPHER_CTX, CipherCTXDeleter> cipher_ctx;
    std::unique_ptr<EVP_MD_CTX, MDCTXDeleter> md_ctx;

    AesCipherParams params;
    AesCipherParams CreateCipherParamsFromPassword(std::string_view password);

};

CryptoGuardCtx::Impl::Impl() {
    OpenSSL_add_all_algorithms();
}

CryptoGuardCtx::Impl::~Impl() {
    cipher_ctx.reset();
    md_ctx.reset();
    EVP_cleanup();
}

void CryptoGuardCtx::Impl::ThrowEVPError() {
    std::array<char, MAX_ERR_SIZE> err_buf{};
    ERR_error_string_n(ERR_get_error(), err_buf.data(), MAX_ERR_SIZE - 1);
    throw std::runtime_error(std::format("EVP error occurred: {}", err_buf.data()));
}

AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0)
        throw std::runtime_error{"Failed to create a key from password"};

    return params;
}

void CryptoGuardCtx::Impl::InitCipherCTX(std::string_view password, int encrypt) {
    cipher_ctx = std::unique_ptr<EVP_CIPHER_CTX, CipherCTXDeleter> { EVP_CIPHER_CTX_new() };

    params = CreateCipherParamsFromPassword(password);
    params.encrypt = encrypt;

    if (!EVP_CipherInit_ex(
            cipher_ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt
        ))
            ThrowEVPError();
}

void CryptoGuardCtx::Impl::InitMDCTX() {
    const EVP_MD *md = EVP_get_digestbyname(MD_ALGO.c_str());
    md_ctx = std::unique_ptr<EVP_MD_CTX, MDCTXDeleter> { EVP_MD_CTX_new() };
    if (!md || !md_ctx || !EVP_DigestInit_ex2(md_ctx.get(), md, NULL))
        ThrowEVPError();
}

void CryptoGuardCtx::Impl::ProcessFile(std::iostream &inStream, std::iostream &outStream) {
    int outLen;
    std::vector<char> inBuf(BLOCK_LEN);
    std::vector<unsigned char> outBuf(BLOCK_LEN + EVP_MAX_BLOCK_LENGTH);

    inStream.read(inBuf.data(), BLOCK_LEN);
    for (auto readLen = inStream.gcount(); readLen > 0; readLen = inStream.gcount()) {
        if (!EVP_CipherUpdate(cipher_ctx.get(), outBuf.data(), &outLen, (unsigned char*)inBuf.data(), readLen))
            ThrowEVPError();
        outStream.write((char *)outBuf.data(), outLen);

        inStream.read(inBuf.data(), BLOCK_LEN);

        if (!inStream.good() || !outStream.good())
            throw std::runtime_error("Error processing input/output filestream.");
    }

    if (!EVP_CipherFinal_ex(cipher_ctx.get(), outBuf.data(), &outLen))
        ThrowEVPError();

    outStream.write((char *)outBuf.data(), outLen);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    unsigned int md_len;
    std::vector<char> inBuf(BLOCK_LEN);
    std::vector<unsigned char> md_value(EVP_MAX_MD_SIZE);

    inStream.read(inBuf.data(), BLOCK_LEN);
    for (auto readLen = inStream.gcount(); readLen > 0; readLen = inStream.gcount()) {
        if (!EVP_DigestUpdate(md_ctx.get(), (unsigned char*)inBuf.data(), readLen))
            ThrowEVPError();

        inStream.read(inBuf.data(), BLOCK_LEN);

        if (!inStream.good())
            throw std::runtime_error("Error processing input/output filestream.");
    }

    if (!EVP_DigestFinal_ex(md_ctx.get(), md_value.data(), &md_len))
        ThrowEVPError();

    std::stringstream res;
    for (const auto& sym: md_value)
        res << std::hex << uint16_t(sym);
    return res.str();
}

CryptoGuardCtx::CryptoGuardCtx(): impl_(std::make_unique<CryptoGuardCtx::Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream.good() || !outStream.good())
        throw std::runtime_error("Error processing input/output filestream.");

    impl_->InitCipherCTX(password, 1);

    impl_->ProcessFile(inStream, outStream);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream.good() || !outStream.good())
        throw std::runtime_error("Error processing input/output filestream.");

    impl_->InitCipherCTX(password, 0);

    impl_->ProcessFile(inStream, outStream);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    if (!inStream.good())
        throw std::runtime_error("Error processing input filestream.");

    impl_->InitMDCTX();

    return impl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
