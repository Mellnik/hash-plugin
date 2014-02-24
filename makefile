GPP = g++
GCC = gcc
OUTPUT = "bin/hash.so"
COMPILER_FLAGS = -c -m32 -fPIC -O3 -DLINUX -w -I./include/ -I./include/SDK/amx/
LIBRARIES = ./lib/cryptopp/libcryptopp.a -lrt -Wl,-Bstatic -lboost_system -lboost_thread -lboost_atomic -lboost_chrono -Wl,-Bdynamic

all:
	$(GCC) $(COMPILER_FLAGS) ./include/SDK/amx/*.c
	$(GPP) $(COMPILER_FLAGS) ./include/SDK/*.cpp
	$(GPP) $(COMPILER_FLAGS) ./src/*.cpp
	$(GPP) -m32 -O2 -fshort-wchar -shared -o $(OUTPUT) *.o $(LIBRARIES)
	-rm -f *.o