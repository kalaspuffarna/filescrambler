#ifndef CRYPT_H
#define CRYPT_H

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

class Cryptor
{
public:

    static void generateKey(CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]);

    static void saveKey(const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE], const std::string &keyDir);

    static void loadKey(CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE], const std::string &keyDir);

    static void encryptFile(const std::string &inputFile, const std::string &outputFile, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]);

    static void decryptFile(const std::string &inputFile, const std::string &outputFile, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]);
};

#endif