#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

using namespace CryptoPP;

void generateKey(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE])
{
    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);
}

void saveKey(const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE], const std::string &keyDir)
{
    std::ofstream keyFile(keyDir + "key.key", std::ios::binary);
    keyFile.write((char *)key, AES::DEFAULT_KEYLENGTH);
    keyFile.write((char *)iv, AES::BLOCKSIZE);
    keyFile.close();
}

void loadKey(byte key[AES::DEFAULT_KEYLENGTH], byte iv[AES::BLOCKSIZE], const std::string &keyDir)
{
    std::ifstream keyFile(keyDir + "key.key", std::ios::binary);
    keyFile.read((char *)key, AES::DEFAULT_KEYLENGTH);
    keyFile.read((char *)iv, AES::BLOCKSIZE);
    keyFile.close();
}

void encryptFile(const std::string &inputFile, const std::string &outputFile, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFile.c_str(), true,
               new StreamTransformationFilter(encryption,
                                              new FileSink(outputFile.c_str())));
}

int main(int argc, char *argv[])
{
    
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <Original file> <Encrypted file> <Key location>" << std::endl;
        return 1;
    }
    
    for (int i{}; i < argc; i++)
    {
        std::ifstream inputFile(argv[i]);
        if (!inputFile)
        {
            std::cerr << "Error: Unable to open file." << std::endl;
            return 1;
        }
        inputFile.close();
    }
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    generateKey(key, iv);
    saveKey(key, iv, argv[3]);

    encryptFile(argv[1], argv[2], key, iv);

    std::cout << "File encrypted successfully." << std::endl;

    return 0;
}
