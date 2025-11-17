#include "rsa.h"
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <random>
#include <iostream>

// ==================== Fungsi Matematika Dasar ====================

// Menghitung GCD (Greatest Common Divisor) menggunakan algoritma Euclidean
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Modular exponentiation: (base^exp) % mod
// Implementasi efisien untuk mencegah overflow
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (__uint128_t)result * base % mod;
        }
        exp = exp >> 1;
        base = (__uint128_t)base * base % mod;
    }
    return result;
}

// Extended Euclidean Algorithm untuk mencari modular inverse
// Mengembalikan d sedemikian sehingga (a * d) % m = 1
int64_t extended_gcd(int64_t a, int64_t b, int64_t* x, int64_t* y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t gcd_val = extended_gcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd_val;
}

// Mencari modular inverse dari a modulo m
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t x, y;
    int64_t g = extended_gcd(a, m, &x, &y);
    if (g != 1) {
        return 0; // Inverse tidak ada
    }
    return (x % m + m) % m;
}

// Miller-Rabin Primality Test
bool miller_rabin(uint64_t n, int iterations = 5) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;

    // Tulis n-1 sebagai 2^r * d
    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    // Witness loop
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(2, n - 2);

    for (int i = 0; i < iterations; i++) {
        uint64_t a = dis(gen);
        uint64_t x = mod_pow(a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        bool composite = true;
        for (int j = 0; j < r - 1; j++) {
            x = mod_pow(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }

        if (composite)
            return false;
    }
    return true;
}

// Generate bilangan prima acak dalam range tertentu
uint64_t generate_prime(uint64_t min, uint64_t max) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(min, max);

    uint64_t candidate;
    do {
        candidate = dis(gen);
        if (candidate % 2 == 0) candidate++; // Pastikan ganjil
    } while (!miller_rabin(candidate, 10));

    return candidate;
}

// ==================== Implementasi RSA ====================

RSAKeyPair rsa_generate_keypair(int bits) {
    int retry_count = 0;
    int max_retries = 100; // Safety limit
    
generate_new_key:
    retry_count++;
    if (retry_count > max_retries) {
        std::cerr << "FATAL: Unable to generate valid RSA key after " << max_retries << " attempts!" << std::endl;
        exit(1);
    }
    
    // Generate dua bilangan prima untuk menghasilkan modulus n-bit
    // bits adalah target size untuk modulus (n = p * q)
    uint64_t p, q;
    
    // Setiap prima harus sekitar bits/2 bit
    // Untuk bits=64, kita butuh primes sekitar 32-bit
    uint64_t min_val = 1ULL << (bits / 2 - 1);
    uint64_t max_val = (1ULL << (bits / 2)) - 1;
    
    // Ensure minimum values for guaranteed safe encryption
    if (bits < 64) {
        // Minimal 64-bit modulus untuk 100% reliability
        min_val = 1ULL << 31;  // 2^31 = 2,147,483,648
        max_val = (1ULL << 32) - 1;  // 2^32-1 = 4,294,967,295
    }
    
    // Generate primes with sufficient separation
    p = generate_prime(min_val, max_val);
    q = generate_prime(min_val, max_val);
    
    // Ensure p and q are different and not too close
    while (p == q || (p > q ? p - q : q - p) < (max_val - min_val) / 100) {
        q = generate_prime(min_val, max_val);
    }

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    // Pilih e (biasanya 65537, tapi kita gunakan nilai yang lebih kecil untuk keamanan)
    uint64_t e = 65537;
    if (e >= phi) {
        e = 3; // Fallback jika phi terlalu kecil
        while (gcd(e, phi) != 1) {
            e += 2;
        }
    }

    // Hitung d (private exponent)
    uint64_t d = mod_inverse(e, phi);
    
    // CRITICAL: Validate key correctness
    // Check 1: d must be valid (not 0)
    if (d == 0) {
        goto generate_new_key; // Retry silently
    }
    
    // Check 2: Verify (d * e) % phi == 1
    __uint128_t test_mult = ((__uint128_t)d * e) % phi;
    if (test_mult != 1) {
        goto generate_new_key; // Retry silently
    }
    
    // Check 3: Test encrypt/decrypt with a simple byte
    uint64_t test_byte = 65; // 'A'
    uint64_t encrypted = mod_pow(test_byte, e, n);
    uint64_t decrypted = mod_pow(encrypted, d, n);
    if (decrypted != test_byte) {
        goto generate_new_key; // Retry silently
    }
    
    // Optional: Show retry count if more than 1 attempt
    if (retry_count > 1) {
        std::cout << "      (Generated valid key after " << retry_count << " attempts)" << std::endl;
    }

    RSAKeyPair keypair;
    keypair.public_key.n = n;
    keypair.public_key.e = e;
    keypair.private_key.n = n;
    keypair.private_key.d = d;

    return keypair;
}

std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, const RSAPublicKey& public_key) {
    std::vector<uint64_t> ciphertext;
    
    for (unsigned char c : plaintext) {
        uint64_t m = static_cast<uint64_t>(c);
        uint64_t encrypted = mod_pow(m, public_key.e, public_key.n);
        ciphertext.push_back(encrypted);
    }
    
    return ciphertext;
}

std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, const RSAPrivateKey& private_key) {
    std::string plaintext;
    
    for (uint64_t c : ciphertext) {
        uint64_t decrypted = mod_pow(c, private_key.d, private_key.n);
        plaintext += static_cast<char>(decrypted);
    }
    
    return plaintext;
}

// ==================== Fungsi Serialisasi ====================

std::string serialize_public_key(const RSAPublicKey& key) {
    std::ostringstream oss;
    oss << key.n << ":" << key.e;
    return oss.str();
}

RSAPublicKey deserialize_public_key(const std::string& serialized) {
    RSAPublicKey key;
    size_t pos = serialized.find(':');
    if (pos != std::string::npos) {
        key.n = std::stoull(serialized.substr(0, pos));
        key.e = std::stoull(serialized.substr(pos + 1));
    }
    return key;
}

std::string serialize_encrypted_data(const std::vector<uint64_t>& encrypted_data) {
    std::ostringstream oss;
    for (size_t i = 0; i < encrypted_data.size(); ++i) {
        if (i > 0) oss << ",";
        oss << encrypted_data[i];
    }
    return oss.str();
}

std::vector<uint64_t> deserialize_encrypted_data(const std::string& serialized) {
    std::vector<uint64_t> data;
    std::istringstream iss(serialized);
    std::string token;
    
    while (std::getline(iss, token, ',')) {
        if (!token.empty()) {
            data.push_back(std::stoull(token));
        }
    }
    
    return data;
}
