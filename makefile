all: imp2p3.cpp
	g++ imp2p3.cpp EncryptionLibrary.cpp -o imp2p3

clean: 
	rm -r imp2p3 rm -rf data