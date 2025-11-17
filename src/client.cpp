#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <mutex>
#include <csignal>
#include <cstdio>
#include "des.h"
#include "rsa.h"

// --- Cross-Platform Socket Headers ---
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    typedef int socket_t;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket(s) close(s)
#endif

// --- Global Variables ---
std::mutex cout_mutex;
socket_t client_socket = INVALID_SOCKET;
std::string session_key; // DES session key yang akan digunakan untuk komunikasi
bool should_exit = false; // Flag untuk mencegah prompt setelah peer exit

// --- Fungsi Bantuan Jaringan ---

void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void handle_signal(int signum) {
    std::cout << "\nMenerima signal " << signum << ". Menutup koneksi dengan aman..." << std::endl;
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    cleanup_sockets();
    exit(signum);
}

void init_sockets() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error: WSAStartup gagal" << std::endl;
        exit(1);
    }
#endif
}

void print_error(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
}

// --- Thread untuk Menerima Pesan ---
void receive_thread(const std::string& peer_username) {
    char buffer[4096];
    while (true) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);

        if (bytes_received <= 0) {
            // Only show disconnect message if not already exiting
            if (!should_exit) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << std::endl << peer_username << " terputus." << std::endl;
            }
            should_exit = true;
            #ifdef _WIN32
                INPUT_RECORD r[1] = {}; 
                r[0].EventType = KEY_EVENT; 
                r[0].Event.KeyEvent.bKeyDown = TRUE; 
                r[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN; 
                DWORD written;
                WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), r, 1, &written);
            #else
                shutdown(STDIN_FILENO, SHUT_RD);
            #endif
            return;
        }

        std::string encrypted_response(buffer, bytes_received);
        try {
            std::string decrypted_response = des_decrypt(encrypted_response, session_key);
            
            // Check for exit command FIRST before displaying
            if (decrypted_response == "/exit") {
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << std::endl << peer_username << " mengakhiri sesi." << std::endl;
                    std::cout << std::endl << "Tekan Enter untuk keluar." << std::endl;
                }
                should_exit = true;
                #ifdef _WIN32
                    INPUT_RECORD r[1] = {}; 
                    r[0].EventType = KEY_EVENT; 
                    r[0].Event.KeyEvent.bKeyDown = TRUE; 
                    r[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN; 
                    DWORD written; 
                    WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), r, 1, &written);
                #else
                    shutdown(STDIN_FILENO, SHUT_RD);
                #endif
                return;
            }
            
            // Display normal message
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << std::endl << peer_username << ": " << decrypted_response << std::endl;
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Dekripsi pesan gagal: " << e.what() << std::endl;
        }
    }
}

// --- Main Program ---

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>" << std::endl;
        return 1;
    }

    std::cout << "=== CLIENT: DES-RSA Encrypted Communication ===" << std::endl;
    std::cout << "Sistem ini menggunakan RSA untuk pertukaran kunci dan DES untuk enkripsi pesan." << std::endl;
    std::cout << std::endl;

    signal(SIGINT, handle_signal);
    init_sockets();

    // === LANGKAH 1: Buat Socket ===
    std::cout << "[1/6] Creating socket..." << std::endl;
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        print_error("Pembuatan socket gagal");
        cleanup_sockets();
        return 1;
    }
    std::cout << "      Socket berhasil dibuat." << std::endl;
    std::cout << std::endl;

    // === LANGKAH 2: Connect ke Server ===
    std::cout << "[2/6] Connecting to server..." << std::endl;
    const char* server_ip = argv[1];
    int port = std::stoi(argv[2]);
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

#ifdef _WIN32
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
#else
    if (inet_addr(server_ip) == INADDR_NONE) {
        std::cerr << "Error: IP address tidak valid" << std::endl;
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
#endif

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        print_error("Koneksi ke server gagal");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }

    std::cout << "      Berhasil terhubung ke server " << server_ip << ":" << port << std::endl;
    std::cout << std::endl;

    // === LANGKAH 3: Terima RSA Public Key dari Server ===
    std::cout << "[3/6] Receiving RSA public key from server..." << std::endl;
    char buffer[4096];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        print_error("Gagal menerima public key dari server");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    
    std::string serialized_public_key(buffer, bytes_received);
    RSAPublicKey server_public_key = deserialize_public_key(serialized_public_key);
    std::cout << "      Public key diterima: (n=" << server_public_key.n 
              << ", e=" << server_public_key.e << ")" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 4: Generate DES Session Key & Encrypt dengan RSA ===
    std::cout << "[4/6] Generating and encrypting DES session key..." << std::endl;
    session_key = generate_random_des_key();
    std::cout << "      DES session key generated: " << session_key << std::endl;
    std::cout << "      Key length: " << session_key.length() << " bytes" << std::endl;
    
    // Encrypt session key dengan RSA public key
    std::vector<uint64_t> encrypted_session_key = rsa_encrypt(session_key, server_public_key);
    std::string encrypted_session_key_str = serialize_encrypted_data(encrypted_session_key);
    
    // Kirim encrypted session key ke server
    if (send(client_socket, encrypted_session_key_str.c_str(), encrypted_session_key_str.length(), 0) == SOCKET_ERROR) {
        print_error("Gagal mengirim encrypted session key");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    std::cout << "      Encrypted session key dikirim ke server." << std::endl;
    std::cout << "      Key exchange berhasil!" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 5: Tukar Username (Terenkripsi dengan DES) ===
    std::cout << "[5/6] Username exchange..." << std::endl;
    std::string my_username, server_username;
    std::cout << "Masukkan username Anda: ";
    std::getline(std::cin, my_username);

    // Kirim username ke server (encrypted)
    std::string encrypted_username = des_encrypt(my_username, session_key);
    send(client_socket, encrypted_username.c_str(), encrypted_username.length(), 0);

    // Terima username dari server (encrypted)
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        print_error("Gagal menerima username dari server");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    server_username = des_decrypt(std::string(buffer, bytes_received), session_key);

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[6/6] Sesi chat dimulai!" << std::endl;
    std::cout << "Anda sekarang terhubung dengan " << server_username << std::endl;
    std::cout << "Ketik '/exit' untuk mengakhiri sesi." << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 6: Komunikasi Chat (DES Encrypted) ===
    std::thread receiver(receive_thread, server_username);
    receiver.detach();

    std::string message;
    while (std::getline(std::cin, message)) {
        if (should_exit || client_socket == INVALID_SOCKET) break;

        // Check for exit command
        if (message == "/exit") {
            should_exit = true;
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Mengakhiri sesi..." << std::endl;
                std::cout << std::endl << "Tekan Enter untuk keluar." << std::endl;
            }
            // Send exit notification to server
            try {
                std::string encrypted_message = des_encrypt("/exit", session_key);
                send(client_socket, encrypted_message.c_str(), encrypted_message.length(), 0);
            } catch (...) {
                // Ignore encryption errors on exit
            }
            break;
        }

        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << my_username << ": " << message << std::endl;
        }
        try {
            std::string encrypted_message = des_encrypt(message, session_key);
            if (send(client_socket, encrypted_message.c_str(), encrypted_message.length(), 0) == SOCKET_ERROR) {
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "Koneksi terputus." << std::endl;
                }
                break;
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Enkripsi pesan gagal: " << e.what() << std::endl;
        }
    }

    // Cleanup
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    cleanup_sockets();
    std::cout << "Koneksi ditutup." << std::endl;

    return 0;
}
