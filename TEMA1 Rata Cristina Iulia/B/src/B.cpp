#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <openssl/opensslconf.h>
#include <openssl/aes.h>

#define PORT 8081
#define KM_PORT 8080
#define ECB_MODE 1
#define CFB_MODE 0
#define Kprim "1234567abcdef123"

std::ofstream fout("textDec.txt", std::ofstream::out);

unsigned char iv[] = "afostcaniciodata", prevIV[AES_BLOCK_SIZE];

void XOR(unsigned char *firstString, const unsigned char *secondString)
{
    for (unsigned int index = 0; index < 16; index++)
    {
        firstString[index] ^= secondString[index];
    }
}

void encAes(const unsigned char *input, unsigned char *output, unsigned char *key)
{
    AES_KEY *aesKey = new AES_KEY();
    AES_set_encrypt_key(key, 128, aesKey);
    AES_encrypt(input, output, aesKey);
}

void decAes(const unsigned char *input, unsigned char *output, unsigned char *key)
{
    AES_KEY *aesKey = new AES_KEY();
    AES_set_decrypt_key(key, 128, aesKey);
    AES_decrypt(input, output, aesKey);
}

int decryptECB(int socket, unsigned char *key)
{
    int nBlocks;
    if (read(socket, &nBlocks, sizeof(int)) < 0)
    {
        perror("Read error ");
        return errno;
    }

    char *block = new char[AES_BLOCK_SIZE];
    for (int i = 0; i < nBlocks; i++)
    {
        if (read(socket, block, AES_BLOCK_SIZE) < 0)
        {
            perror("Read error ");
            return errno;
        }

        decAes((unsigned char *)block, (unsigned char *)block, key);
        fout<<block;
    }
}

int decryptCFB(int socket, unsigned char *key)
{
    int nBlocks;
    if (read(socket, &nBlocks, sizeof(int)) < 0)
    {
        perror("Write error ");
        return errno;
    }
    memcpy((char *)prevIV, (const char *)iv, AES_BLOCK_SIZE);

    for (int i = 0; i < nBlocks; i++)
    {
        char *block = new char[AES_BLOCK_SIZE];

        if (read(socket, block, AES_BLOCK_SIZE) < 0)
        {
            perror("Read error");
            return errno;
        }


        unsigned char *res = new unsigned char[AES_BLOCK_SIZE];
        encAes(prevIV, res, (unsigned char *)key);

        XOR(res, (unsigned char *)block);
        memcpy((char *)prevIV, (const char *)block, AES_BLOCK_SIZE);

        fout<<res;

    }
}

int main()
{

    char Kkey[AES_BLOCK_SIZE];

    int nodeA;
    struct sockaddr_in server;

    if ((nodeA = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error ");
        return errno;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if (connect(nodeA, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("Connect error ");
        exit(1);
    }

    int mode;

    if (read(nodeA, &mode, sizeof(int)) < 0)
    {
        perror("Read error ");
        return errno;
    }

    if (read(nodeA, Kkey, AES_BLOCK_SIZE) < 0)
    {
        perror("Read error ");
        return errno;
    }

    decAes((unsigned char *)Kkey, (unsigned char *)Kkey, (unsigned char *)Kprim);

    if(mode==1)
        decryptECB(nodeA,(unsigned char*)Kkey);
    else
        decryptCFB(nodeA, (unsigned char *)Kkey);
        
    fout.close();
}