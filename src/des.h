#ifndef DES_H
#define DES_H

#include <string>
#include <vector>

// Deklarasi fungsi utama untuk enkripsi dan dekripsi DES
std::string des_encrypt(const std::string& plaintext, const std::string& key);
std::string des_decrypt(const std::string& ciphertext, const std::string& key);

// Fungsi tambahan untuk generate random key
std::string generate_random_des_key();

#endif // DES_H
