| Nama                   | NRP        | Kelas |
| ---------------------- | ---------- | ----- |
| Aryaka Leorgi Eprideka | 5025231117 | C     |
| Naswan Nashir Ramadhan | 5025231246 | C     |

# DES-RSA Encrypted Communication System

Sistem komunikasi client-server dengan enkripsi hybrid menggunakan RSA untuk pertukaran kunci dan DES untuk enkripsi pesan.

## Deskripsi

Project ini mengimplementasikan konsep *public key distribution of secret keys* dimana:
- Server dan client tidak perlu berbagi kunci rahasia sebelumnya
- RSA digunakan untuk mentransfer kunci sesi DES dengan aman
- DES digunakan untuk enkripsi pesan komunikasi (lebih cepat dari RSA)
- Setiap sesi menggunakan kunci unik yang di-generate secara random

**Catatan**: Implementasi ini untuk tujuan pembelajaran. Untuk produksi, gunakan library standar seperti OpenSSL dengan RSA 2048-bit+ dan AES-256.

## Cara Penggunaan

### Kompilasi

**Windows:**
```cmd
.\build.bat
```

**Linux/macOS:**
```bash
make
```

### Menjalankan

1. **Start Server** (terminal pertama):
```bash
.\server.exe 8080        # Windows
./server 8080            # Linux/macOS
```

2. **Connect Client** (terminal kedua):
```bash
.\client.exe 127.0.0.1 8080    # Windows
./client 127.0.0.1 8080        # Linux/macOS
```

3. Masukkan username saat diminta
4. Mulai chat - semua pesan otomatis terenkripsi
5. Ketik `/exit` untuk keluar

## Alur Kerja Key Exchange

```
Client                          Server
  |                               |
  |<-------- Public Key ----------|  1. Server kirim RSA public key
  |                               |
  | 2. Generate random DES key    |
  | 3. Encrypt DES key dgn RSA    |
  |                               |
  |------- Encrypted Key -------->|  4. Client kirim encrypted key
  |                               |
  |                               |  5. Server decrypt dengan private key
  |<==== Chat with DES Key ======>|  6. Komunikasi menggunakan DES
```

Keuntungan:
- Tidak perlu pre-shared secret
- Session key berbeda setiap koneksi
- Key tidak pernah dikirim dalam plaintext

## Struktur Project

```
src/
  ├── rsa.h, rsa.cpp      # Implementasi RSA (key generation, encrypt/decrypt)
  ├── des.h, des.cpp      # Implementasi DES (encrypt/decrypt, padding)
  ├── server.cpp          # Server dengan RSA key exchange
  └── client.cpp          # Client dengan random key generation
build.bat                 # Script kompilasi Windows
Makefile                  # Script kompilasi Linux/macOS
```

## Implementasi

### RSA Module
- RSA key pair generation (64-bit modulus for demo)
- Miller-Rabin primality testing
- Modular arithmetic with __uint128_t for overflow prevention
- **Key validation**: Auto-reject invalid keys, retry until valid
- Public/private key encryption/decryption (byte-per-byte)
- Serialization untuk network transfer

### DES Module  
- 16-round Feistel network
- PKCS#5 padding
- Random secure key generation

### Network Communication
- TCP/IP socket
- Multithreading untuk full-duplex communication
- Cross-platform support (Windows/Linux)

## Security Notes

**Kelebihan:**
- No pre-shared secret required
- Forward secrecy (different key per session)
- Cryptographically secure RNG
- **Automatic key validation**: Invalid keys auto-rejected (100% reliability)
- Hybrid approach (RSA for key exchange, DES for bulk data)

**Limitasi:**
- RSA key size kecil (64-bit) untuk demo - produksi butuh 2048+ bit
- DES sudah deprecated - seharusnya pakai AES-256
- Tidak ada authentication - vulnerable to MITM
- Tidak ada message integrity check (HMAC)
- Deterministic encryption (no padding scheme)

Untuk produksi: gunakan TLS/SSL library seperti OpenSSL.

## Troubleshooting

**Port already in use:**
```bash
# Windows: cari process
netstat -ano | findstr :8080
# Linux: kill process
sudo lsof -i :8080
```

**Connection refused:**
- Pastikan server sudah running
- Check firewall settings
- Verify IP address dan port

## License

MIT License - See LICENSE file for details.
