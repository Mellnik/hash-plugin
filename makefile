GPP = g++
GCC = gcc
OUTPUT = "bin/hash.so"
COMPILER_FLAGS = -c -m32 -fPIC -O3 -DLINUX -w -I./include/ -I./include/SDK/amx/
LIBRARIES = ./lib/libcryptopp.a -lrt
CRYPTOPP_SRC_DIR = ./src/cryptopp

all: cryptolib hash clean

hash:
	$(GCC) $(COMPILER_FLAGS) ./include/SDK/amx/*.c
	$(GPP) -std=gnu++17 $(COMPILER_FLAGS) ./include/SDK/*.cpp
	$(GPP) -std=gnu++17 $(COMPILER_FLAGS) ./src/*.cpp
	mkdir -p bin
	$(GPP) -m32 -O2 -fshort-wchar -shared -o $(OUTPUT) *.o $(LIBRARIES)
	
cryptolib:
	$(MAKE) -C $(CRYPTOPP_SRC_DIR) static
	mkdir -p lib
	cp $(CRYPTOPP_SRC_DIR)/libcryptopp.a ./lib
	
clean:
	rm -f *.o
