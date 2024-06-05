#include "crypt.h"

int main(int argc, char *argv[])
{
    if (std::string(argv[1]) == "-e")
    {
        if (argc != 5)
        {
            std::cerr << "Usage: " << argv[0] << " <Original file> <Encrypted file> <Key location>" << std::endl;
            return 1;
        }
        std::cout << argv[4] << std::endl;
        for (int i{}; i < argc; i++)
        {
            std::ifstream inputFile(argv[i]);
            if (!inputFile && i != 4 && i != 1)
            {
                std::cout << i << std::endl;
                std::cerr << "Error: Unable to open file." << std::endl;
                return 1;
            }
            inputFile.close();
        }
        CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
        Cryptor::generateKey(key, iv);
        Cryptor::saveKey(key, iv, argv[4]);

        Cryptor::encryptFile(argv[2], argv[3], key, iv);

        std::cout << "File encrypted successfully." << std::endl;

        return 0;
    }
    else if (std::string(argv[1]) == "-d")
    {
        if (argc != 5)
        {
            std::cerr << "Usage: " << argv[0] << " <Encrypted file> <Output file> <Key location>" << std::endl;
            return 1;
        }

        for (int i{}; i < argc; i++)
        {
            std::ifstream inputFile(argv[i]);
            if (!inputFile && i != 4 && i != 1)
            {
                std::cerr << "Error: Unable to open file." << std::endl;
                return 1;
            }
            inputFile.close();
        }

        CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

        Cryptor::loadKey(key, iv, argv[4]);

        Cryptor::decryptFile(argv[2], argv[3], key, iv);

        std::cout << "File decrypted successfully." << std::endl;

        return 0;
    }
    else
    {
        std::cerr << "Usage: " << argv[0] << " <-e/-d> <Input file> <Output file> <Key location>" << std::endl;
        return 1;
    }
}