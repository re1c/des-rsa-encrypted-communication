# Makefile for DES-RSA Encrypted Communication Project

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Isrc

# Source files
SRC_DIR = src
DES_SRC = $(SRC_DIR)/des.cpp
RSA_SRC = $(SRC_DIR)/rsa.cpp
SERVER_SRC = $(SRC_DIR)/server.cpp
CLIENT_SRC = $(SRC_DIR)/client.cpp

# Executable names
SERVER_EXEC = server
CLIENT_EXEC = client

# Default target
all: $(SERVER_EXEC) $(CLIENT_EXEC)

# OS-specific settings
ifeq ($(OS),Windows_NT)
    # Windows settings
    LIBS = -lws2_32 -lpthread
    SERVER_EXEC := $(SERVER_EXEC).exe
    CLIENT_EXEC := $(CLIENT_EXEC).exe
    RM = del /Q
    # Fix for path separators in Windows
    fix_path = $(subst /,\,$(1))
else
    # Linux/macOS settings
    LIBS = -pthread
    RM = rm -f
    fix_path = $(1)
endif

# Target to build the server
$(SERVER_EXEC): $(SERVER_SRC) $(DES_SRC) $(RSA_SRC)
	@echo "Building server..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "Server build complete: $(SERVER_EXEC)"

# Target to build the client
$(CLIENT_EXEC): $(CLIENT_SRC) $(DES_SRC) $(RSA_SRC)
	@echo "Building client..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "Client build complete: $(CLIENT_EXEC)"

# Target to clean up build files
clean:
	@echo "Cleaning build files..."
	$(RM) $(call fix_path, $(SERVER_EXEC)) $(call fix_path, $(CLIENT_EXEC))
	@echo "Clean complete."

# Help target
help:
	@echo "DES-RSA Encrypted Communication - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all     - Build both server and client (default)"
	@echo "  server  - Build server only"
	@echo "  client  - Build client only"
	@echo "  clean   - Remove compiled executables"
	@echo "  help    - Display this help message"

.PHONY: all clean help
