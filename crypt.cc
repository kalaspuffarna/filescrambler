#include "crypt.h"

using namespace CryptoPP;

void Cryptor::generateKey(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE])
{
    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);
}

void Cryptor::saveKey(const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE], const std::string &keyDir)
{
    std::ofstream keyFile(keyDir + "key.key", std::ios::binary);
    keyFile.write((char *)key, AES::DEFAULT_KEYLENGTH);
    keyFile.write((char *)iv, AES::BLOCKSIZE);
    keyFile.close();
}

void Cryptor::encryptFile(const std::string &inputFile, const std::string &outputFile, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFile.c_str(), true,
               new StreamTransformationFilter(encryption,
                                              new FileSink(outputFile.c_str())));
}


void Cryptor::loadKey(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE], const std::string& keyDir) {
    std::ifstream keyFile(keyDir + "key.key", std::ios::binary);
    keyFile.read((char*)key, AES::DEFAULT_KEYLENGTH);
    keyFile.read((char*)iv, AES::BLOCKSIZE);
    keyFile.close();
}

void Cryptor::decryptFile(const std::string& inputFile, const std::string& outputFile, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]) {
    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFile.c_str(), true, 
        new StreamTransformationFilter(decryption, 
            new FileSink(outputFile.c_str())
        )
    );
}