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
    #include <netdb.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    typedef int socket_t;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket(s) close(s)
#endif

// --- Global Variables ---
std::mutex cout_mutex;
socket_t listen_socket = INVALID_SOCKET;
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
    if (listen_socket != INVALID_SOCKET) {
        closesocket(listen_socket);
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

std::string get_local_ip() {
    char host_name[256];
    if (gethostname(host_name, sizeof(host_name)) == SOCKET_ERROR) {
        return "<unknown>";
    }
    hostent* host_entry = gethostbyname(host_name);
    if (host_entry == nullptr) {
        return "<unknown>";
    }
    char* ip_addr = inet_ntoa(*(struct in_addr*)*host_entry->h_addr_list);
    return std::string(ip_addr);
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

        std::string encrypted_msg(buffer, bytes_received);
        try {
            std::string decrypted_msg = des_decrypt(encrypted_msg, session_key);
            
            // Check for exit command FIRST before displaying
            if (decrypted_msg == "/exit") {
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
                std::cout << std::endl << peer_username << ": " << decrypted_msg << std::endl;
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Dekripsi pesan gagal: " << e.what() << std::endl;
        }
    }
}

// --- Main Program ---

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    std::cout << "=== SERVER: DES-RSA Encrypted Communication ===" << std::endl;
    std::cout << "Sistem ini menggunakan RSA untuk pertukaran kunci dan DES untuk enkripsi pesan." << std::endl;
    std::cout << std::endl;

    signal(SIGINT, handle_signal);
    init_sockets();

    // === LANGKAH 1: Generate RSA Key Pair ===
    std::cout << "[1/6] Generating RSA key pair..." << std::endl;
    RSAKeyPair rsa_keypair = rsa_generate_keypair(64);  // 64-bit for guaranteed safe encryption
    std::cout << "      RSA Public Key (n, e): (" << rsa_keypair.public_key.n 
              << ", " << rsa_keypair.public_key.e << ")" << std::endl;
    std::cout << "      RSA key pair berhasil dibuat." << std::endl;
    std::cout << std::endl;

    // === LANGKAH 2: Setup Socket Server ===
    std::cout << "[2/6] Setting up server socket..." << std::endl;
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket == INVALID_SOCKET) {
        print_error("Pembuatan socket gagal");
        cleanup_sockets();
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        print_error("setsockopt(SO_REUSEADDR) gagal");
        closesocket(listen_socket);
        cleanup_sockets();
        return 1;
    }

    int port = std::stoi(argv[1]);
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        print_error("Bind gagal");
        closesocket(listen_socket);
        cleanup_sockets();
        return 1;
    }

    if (listen(listen_socket, 1) == SOCKET_ERROR) {
        print_error("Listen gagal");
        closesocket(listen_socket);
        cleanup_sockets();
        return 1;
    }

    std::cout << "      Server listening pada " << get_local_ip() << ":" << port << std::endl;
    std::cout << "      Menunggu client untuk terhubung..." << std::endl;
    std::cout << std::endl;

    // === LANGKAH 3: Accept Client Connection ===
    std::cout << "[3/6] Waiting for client connection..." << std::endl;
    client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket == INVALID_SOCKET) {
        print_error("Accept gagal");
        closesocket(listen_socket);
        cleanup_sockets();
        return 1;
    }

    closesocket(listen_socket);
    listen_socket = INVALID_SOCKET;
    std::cout << "      Client berhasil terhubung!" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 4: RSA Key Exchange ===
    std::cout << "[4/6] Performing RSA key exchange..." << std::endl;
    
    // Kirim public key ke client
    std::string serialized_public_key = serialize_public_key(rsa_keypair.public_key);
    if (send(client_socket, serialized_public_key.c_str(), serialized_public_key.length(), 0) == SOCKET_ERROR) {
        print_error("Gagal mengirim public key");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    std::cout << "      Public key dikirim ke client." << std::endl;

    // Terima encrypted DES session key dari client
    char buffer[4096];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        print_error("Gagal menerima encrypted session key dari client");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    
    std::string encrypted_session_key_str(buffer, bytes_received);
    std::vector<uint64_t> encrypted_session_key = deserialize_encrypted_data(encrypted_session_key_str);
    
    // Decrypt session key menggunakan RSA private key
    session_key = rsa_decrypt(encrypted_session_key, rsa_keypair.private_key);
    std::cout << "      Session key berhasil diterima dan didekripsi." << std::endl;
    std::cout << "      >> Decrypted session key: " << session_key << std::endl;
    std::cout << "      Key exchange berhasil!" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 5: Tukar Username (Terenkripsi dengan DES) ===
    std::cout << "[5/6] Username exchange..." << std::endl;
    std::string my_username, client_username;
    std::cout << "Masukkan username Anda: ";
    std::getline(std::cin, my_username);

    // Terima username dari client (encrypted)
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        print_error("Gagal menerima username dari client");
        closesocket(client_socket);
        cleanup_sockets();
        return 1;
    }
    client_username = des_decrypt(std::string(buffer, bytes_received), session_key);

    // Kirim username ke client (encrypted)
    std::string encrypted_username = des_encrypt(my_username, session_key);
    send(client_socket, encrypted_username.c_str(), encrypted_username.length(), 0);

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[6/6] Sesi chat dimulai!" << std::endl;
    std::cout << "Anda sekarang terhubung dengan " << client_username << std::endl;
    std::cout << "Ketik '/exit' untuk mengakhiri sesi." << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // === LANGKAH 6: Komunikasi Chat (DES Encrypted) ===
    std::thread receiver(receive_thread, client_username);
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
            // Send exit notification to client
            try {
                std::string encrypted_response = des_encrypt("/exit", session_key);
                send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
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
            std::string encrypted_response = des_encrypt(message, session_key);
            if (send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0) == SOCKET_ERROR) {
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
