#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>
#include <iomanip>
#include <sstream>

// ========== APP SECURITY: Hardware-Accelerated Crypto ==========
class CryptoEngine {
private:
    static constexpr int KEY_SIZE = 32;  // 256-bit
    static constexpr int IV_SIZE = 16;   // 128-bit
    static constexpr int ITERATIONS = 100000; // PBKDF2 iterations

    // Secure memory wipe
    void secureZero(void* ptr, size_t len) {
        volatile char* p = (volatile char*)ptr;
        while (len--) *p++ = 0;
    }

public:
    // ========== APP SECURITY: Constant-time comparison ==========
    bool secureCompare(const std::string& a, const std::string& b) {
        if (a.length() != b.length()) return false;
        volatile int result = 0;
        for (size_t i = 0; i < a.length(); i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // ========== APP SECURITY: AES-256-GCM Encryption ==========
    std::string encryptAES(const std::string& plaintext, const std::string& password) {
        // Derive key using PBKDF2
        unsigned char key[KEY_SIZE];
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));
        
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         salt, sizeof(salt),
                         ITERATIONS, EVP_sha256(),
                         KEY_SIZE, key);

        // Generate IV
        unsigned char iv[IV_SIZE];
        RAND_bytes(iv, sizeof(iv));

        // Encrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
        
        std::vector<unsigned char> ciphertext(plaintext.length() + 16);
        int len = 0, ciphertext_len = 0;
        
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          (unsigned char*)plaintext.c_str(), plaintext.length());
        ciphertext_len = len;
        
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        
        // Get authentication tag
        unsigned char tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        
        EVP_CIPHER_CTX_free(ctx);
        secureZero(key, KEY_SIZE);

        // Combine salt + iv + tag + ciphertext
        std::string result;
        result.append((char*)salt, sizeof(salt));
        result.append((char*)iv, IV_SIZE);
        result.append((char*)tag, 16);
        result.append((char*)ciphertext.data(), ciphertext_len);
        
        return result;
    }

    // ========== APP SECURITY: Decryption with verification ==========
    std::string decryptAES(const std::string& ciphertext, const std::string& password) {
        if (ciphertext.length() < 16 + 16 + 16) {
            throw std::runtime_error("Invalid ciphertext");
        }

        // Extract salt, iv, tag
        const unsigned char* data = (unsigned char*)ciphertext.data();
        std::vector<unsigned char> salt(data, data + 16);
        std::vector<unsigned char> iv(data + 16, data + 16 + 16);
        std::vector<unsigned char> tag(data + 16 + 16, data + 16 + 16 + 16);
        std::vector<unsigned char> encrypted(data + 16 + 16 + 16, 
                                            data + ciphertext.length());

        // Derive key
        unsigned char key[KEY_SIZE];
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         salt.data(), salt.size(),
                         ITERATIONS, EVP_sha256(),
                         KEY_SIZE, key);

        // Decrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv.data());
        
        std::vector<unsigned char> plaintext(encrypted.size() + 1);
        int len = 0, plaintext_len = 0;
        
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          encrypted.data(), encrypted.size());
        plaintext_len = len;
        
        // Verify tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            secureZero(key, KEY_SIZE);
            throw std::runtime_error("Decryption failed - invalid tag");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        secureZero(key, KEY_SIZE);
        
        return std::string((char*)plaintext.data(), plaintext_len);
    }

    // ========== INTERNET SECURITY: Secure Hash for Password ==========
    std::string hashPassword(const std::string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));
        
        // Using SHA-256 with salt
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, salt, sizeof(salt));
        SHA256_Update(&sha256, password.c_str(), password.length());
        SHA256_Final(hash, &sha256);
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::setw(2) << (int)hash[i];
        }
        return ss.str();
    }
};

// Export for other languages
extern "C" {
    CryptoEngine* create_engine() { return new CryptoEngine(); }
    void destroy_engine(CryptoEngine* engine) { delete engine; }
    const char* encrypt(CryptoEngine* engine, const char* text, const char* pass) {
        static std::string result;
        result = engine->encryptAES(text, pass);
        return result.c_str();
    }
    const char* decrypt(CryptoEngine* engine, const char* cipher, const char* pass) {
        static std::string result;
        try {
            result = engine->decryptAES(cipher, pass);
        } catch(...) {
            result = "ERROR";
        }
        return result.c_str();
    }
}
