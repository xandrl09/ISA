CC=g++
CFLAGS=-std=c++14 -Wall -Wextra -pedantic

build:	sslsniff.cpp
	$(CC) $(CFLAGS) sslsniff.cpp -o sslsniff -lpcap
