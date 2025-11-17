#ifndef RSA_H
#define RSA_H

#include <string>
#include <vector>
#include <cstdint>

// Struktur untuk menyimpan kunci RSA
struct RSAPublicKey {
    uint64_t n;  // Modulus
    uint64_t e;  // Public exponent
};

struct RSAPrivateKey {
    uint64_t n;  // Modulus
    uint64_t d;  // Private exponent
};

struct RSAKeyPair {
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
};

// Fungsi utama RSA
RSAKeyPair rsa_generate_keypair(int bits = 32);
std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, const RSAPublicKey& public_key);
std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, const RSAPrivateKey& private_key);

// Fungsi utilitas untuk serialisasi
std::string serialize_public_key(const RSAPublicKey& key);
RSAPublicKey deserialize_public_key(const std::string& serialized);
std::string serialize_encrypted_data(const std::vector<uint64_t>& encrypted_data);
std::vector<uint64_t> deserialize_encrypted_data(const std::string& serialized);

#endif // RSA_H
