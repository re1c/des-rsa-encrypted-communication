#include "des.h"
#include <stdexcept>
#include <bitset>
#include <vector>
#include <random>
#include <chrono>

// Tipe data internal untuk representasi biner
typedef std::string binary_str;

// --- Konstanta dan Tabel Standar DES ---
const int IP[] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
const int FP[] = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
const int E[] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
const int P[] = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
const int PC1[] = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
const int PC2[] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
const int S[8][4][16] = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

// --- Deklarasi Fungsi Internal ---
binary_str permute(const binary_str& in, const int* table, int size);
binary_str shift_left(binary_str key, int n);
binary_str xor_str(const binary_str& a, const binary_str& b);
void generate_keys(const binary_str& key, binary_str sub_keys[16]);
binary_str feistel_func(binary_str R, binary_str K);
binary_str process_block(binary_str block, const binary_str sub_keys[16], bool is_encrypt);
std::string add_padding(const std::string& data);
std::string remove_padding(const std::string& data);
binary_str string_to_binary(const std::string& ascii_str);
std::string binary_to_string(const binary_str& bin_str);

// --- Implementasi Fungsi Inti DES ---

binary_str permute(const binary_str& in, const int* table, int size) {
    binary_str out = "";
    out.reserve(size);
    for (int i = 0; i < size; i++) {
        out += in[table[i] - 1];
    }
    return out;
}

binary_str shift_left(binary_str key, int n) {
    return key.substr(n) + key.substr(0, n);
}

binary_str xor_str(const binary_str& a, const binary_str& b) {
    binary_str res = "";
    res.reserve(a.length());
    for (size_t i = 0; i < a.length(); i++) {
        res += (a[i] == b[i] ? '0' : '1');
    }
    return res;
}

void generate_keys(const binary_str& key, binary_str sub_keys[16]) {
    int shifts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
    binary_str K = permute(key, PC1, 56);
    binary_str C = K.substr(0, 28);
    binary_str D = K.substr(28, 28);
    for (int i = 0; i < 16; i++) {
        C = shift_left(C, shifts[i]);
        D = shift_left(D, shifts[i]);
        sub_keys[i] = permute(C + D, PC2, 48);
    }
}

binary_str feistel_func(binary_str R, binary_str K) {
    binary_str ER = permute(R, E, 48);
    binary_str X = xor_str(ER, K);
    binary_str res = "";
    res.reserve(32);
    for (int i = 0; i < 8; i++) {
        binary_str chunk = X.substr(i * 6, 6);
        int row = std::stoi(std::string("") + chunk[0] + chunk[5], nullptr, 2);
        int col = std::stoi(chunk.substr(1, 4), nullptr, 2);
        res += std::bitset<4>(S[i][row][col]).to_string();
    }
    return permute(res, P, 32);
}

binary_str process_block(binary_str block, const binary_str sub_keys[16], bool is_encrypt) {
    block = permute(block, IP, 64);
    binary_str L = block.substr(0, 32);
    binary_str R = block.substr(32, 32);
    for (int i = 0; i < 16; i++) {
        binary_str temp = R;
        int key_idx = is_encrypt ? i : 15 - i;
        R = xor_str(L, feistel_func(R, sub_keys[key_idx]));
        L = temp;
    }
    return permute(R + L, FP, 64);
}

// --- Implementasi Fungsi Padding (PKCS#5) ---

std::string add_padding(const std::string& data) {
    std::string padded_data = data;
    size_t pad_len = 8 - (data.length() % 8);
    char pad_char = static_cast<char>(pad_len);
    for (size_t i = 0; i < pad_len; ++i) {
        padded_data += pad_char;
    }
    return padded_data;
}

std::string remove_padding(const std::string& data) {
    if (data.empty()) {
        return "";
    }
    size_t pad_len = static_cast<size_t>(data.back());
    if (pad_len == 0 || pad_len > 8 || pad_len > data.length()) {
        return data;
    }
    for (size_t i = 1; i <= pad_len; ++i) {
        if (static_cast<size_t>(data[data.length() - i]) != pad_len) {
            return data;
        }
    }
    return data.substr(0, data.length() - pad_len);
}

// --- Implementasi Fungsi Konversi ---

binary_str string_to_binary(const std::string& ascii_str) {
    binary_str bin_str = "";
    for (char c : ascii_str) {
        bin_str += std::bitset<8>(c).to_string();
    }
    return bin_str;
}

std::string binary_to_string(const binary_str& bin_str) {
    std::string ascii_str = "";
    for (size_t i = 0; i < bin_str.length(); i += 8) {
        std::string byte_str = bin_str.substr(i, 8);
        char c = static_cast<char>(std::bitset<8>(byte_str).to_ulong());
        ascii_str += c;
    }
    return ascii_str;
}

// --- Implementasi Fungsi Utama (Interface) ---

std::string des_encrypt(const std::string& plaintext, const std::string& key) {
    if (key.length() != 8) {
        throw std::invalid_argument("Kunci DES harus tepat 8 karakter.");
    }

    binary_str sub_keys[16];
    generate_keys(string_to_binary(key), sub_keys);

    std::string padded_plaintext = add_padding(plaintext);
    
    std::string ciphertext = "";
    for (size_t i = 0; i < padded_plaintext.length(); i += 8) {
        std::string block_str = padded_plaintext.substr(i, 8);
        binary_str block_bin = string_to_binary(block_str);
        binary_str processed_block_bin = process_block(block_bin, sub_keys, true);
        ciphertext += binary_to_string(processed_block_bin);
    }

    return ciphertext;
}

std::string des_decrypt(const std::string& ciphertext, const std::string& key) {
    if (key.length() != 8) {
        throw std::invalid_argument("Kunci DES harus tepat 8 karakter.");
    }
    if (ciphertext.length() % 8 != 0) {
        throw std::invalid_argument("Ciphertext tidak valid (panjang bukan kelipatan 8).");
    }

    binary_str sub_keys[16];
    generate_keys(string_to_binary(key), sub_keys);

    std::string decrypted_padded_text = "";
    for (size_t i = 0; i < ciphertext.length(); i += 8) {
        std::string block_str = ciphertext.substr(i, 8);
        binary_str block_bin = string_to_binary(block_str);
        binary_str processed_block_bin = process_block(block_bin, sub_keys, false);
        decrypted_padded_text += binary_to_string(processed_block_bin);
    }

    return remove_padding(decrypted_padded_text);
}

// --- Fungsi Generate Random DES Key ---

std::string generate_random_des_key() {
    // Gunakan hanya alphanumeric untuk keamanan transmisi RSA
    const char charset[] = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    std::string key;
    key.reserve(8);
    
    for (int i = 0; i < 8; ++i) {
        key += charset[dis(gen)];
    }
    
    return key;
}
