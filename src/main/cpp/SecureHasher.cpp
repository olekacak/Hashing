#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <jni.h>
#include "com_secure_SecureHasher.h"

// Function prototypes
std::string hashAndEncryptNative(const std::string &input, const std::string &publicKey);
std::vector<unsigned char> encryptWithPublicKey(const std::string &hash, const std::string &publicKey);
std::string base64Encode(const std::vector<unsigned char> &data);

extern "C"
JNIEXPORT jstring JNICALL
Java_com_secure_SecureHasher_hashAndEncrypt(JNIEnv *env, jobject obj, jstring input, jstring publicKey) {
    const char *inputChars = env->GetStringUTFChars(input, NULL);
    const char *publicKeyChars = env->GetStringUTFChars(publicKey, NULL);

    if (!inputChars || !publicKeyChars) {
        return env->NewStringUTF("Error: Null input received");
    }

    std::string encryptedHash;
    try {
        encryptedHash = hashAndEncryptNative(inputChars, publicKeyChars);
    } catch (const std::exception &e) {
        encryptedHash = std::string("Error: ") + e.what();
    }

    env->ReleaseStringUTFChars(input, inputChars);
    env->ReleaseStringUTFChars(publicKey, publicKeyChars);

    return env->NewStringUTF(encryptedHash.c_str());
}

std::string hashAndEncryptNative(const std::string &input, const std::string &publicKey) {
    std::cerr << "[DEBUG] Hashing input: " << input << std::endl;

    // Compute SHA-256 hash of input
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(mdctx, input.c_str(), input.length()) <= 0 ||
        EVP_DigestFinal_ex(mdctx, hash, &hashLen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error computing hash");
    }

    EVP_MD_CTX_free(mdctx);

    std::string hashStr(reinterpret_cast<char *>(hash), hashLen);
    std::vector<unsigned char> encrypted = encryptWithPublicKey(hashStr, publicKey);
    return base64Encode(encrypted);
}

std::vector<unsigned char> encryptWithPublicKey(const std::string &hash, const std::string &publicKey) {
    std::cerr << "[DEBUG] Received Public Key:\n" << publicKey << std::endl;

    BIO *bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    if (!bio) {
        throw std::runtime_error("Error creating BIO");
    }

    EVP_PKEY *evp_pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!evp_pkey) {
        throw std::runtime_error("Error loading public key. Ensure the PEM format is correct.");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(evp_pkey);
        throw std::runtime_error("Error creating encryption context");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        throw std::runtime_error("Error initializing encryption");
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)hash.c_str(), hash.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        throw std::runtime_error("Error determining encrypted length");
    }

    std::vector<unsigned char> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, (const unsigned char *)hash.c_str(), hash.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        throw std::runtime_error("Error encrypting data");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_pkey);

    return encrypted;
}

std::string base64Encode(const std::vector<unsigned char> &data) {
    static const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}
