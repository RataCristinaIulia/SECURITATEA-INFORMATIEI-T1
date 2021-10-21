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
#include <openssl/opensslconf.h>
#include <openssl/aes.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <openssl/rand.h>

#define PORT 8081
#define KM_PORT 8080
#define ECB_MODE 1
#define CFB_MODE 0

#define Kprim "1234567abcdef123"

//cere de la KM cheia criptata
bool askForKey(char *key, int mode)
{
    int serverDescriptor;
    struct sockaddr_in server;

    if ((serverDescriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error ");
        return errno;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(KM_PORT);

    if (connect(serverDescriptor, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("Connect error ");
        exit(1);
    }

    if (write(serverDescriptor, &mode, sizeof(int)) < 0)
    {
        perror("Write error ");
        exit(1);
    }

    unsigned int size = AES_BLOCK_SIZE;

    if (read(serverDescriptor, key, size) < 0)
    {
        perror("Read error ");
        return false;
    }

    return true;
}


unsigned char iv[] = "afostcaniciodata", prevIV[AES_BLOCK_SIZE];


void XOR(unsigned char *firstString, const unsigned char *secondString)
{
    for (unsigned int index = 0; index < 16; index++)
    {
        firstString[index] ^= secondString[index];
    }
}

char **getBlocks(char *ptext, int &n)
{
    int l = strlen(ptext);
    int noOfBlocks = l / AES_BLOCK_SIZE;

    char **blocks;
    if (l % AES_BLOCK_SIZE == 0)
        blocks = new char *[noOfBlocks];
    else
        blocks = new char *[noOfBlocks + 1];

    int i, j;
    for (i = 0; i < noOfBlocks; i++)
    {
        blocks[i] = new char[AES_BLOCK_SIZE];
        for (j = 0; j < 16; j++)
            blocks[i][j] = ptext[16 * i + j];
    }
    if (l % AES_BLOCK_SIZE != 0)
    {
        blocks[noOfBlocks] = new char[AES_BLOCK_SIZE];
        for (i = 0; i < 16; i++)
            if (16 * noOfBlocks + i < l - 1)
            {
                //std::cout << ptext[16 * noOfBlocks + i]<<"poz"<<16*noOfBlocks+i<<"\n";
                blocks[noOfBlocks][i] = ptext[16 * noOfBlocks + i];
            }
            else
                blocks[noOfBlocks][i] = NULL;
        n = noOfBlocks + 1;
    }
    else
        n = noOfBlocks;
    return blocks;
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

int encryptECB(const unsigned char **blocks, int nBlocks, int socket, unsigned char *key)
{

    if (write(socket, &nBlocks, sizeof(int)) < 0)
    {
        perror("Write error ");
        return errno;
    }
    for (int i = 0; i < nBlocks; i++)
    {
        char *encBlock = new char[AES_BLOCK_SIZE];
        encAes((unsigned char *)blocks[i], (unsigned char *)encBlock, (unsigned char *)key);

        if (write(socket, encBlock, AES_BLOCK_SIZE) < 0)
        {
            perror("Write error ");
            return errno;
        }
    }
}

int encryptCFB(unsigned char **blocks, int nBlocks, int socket, unsigned char *key)
{

    if (write(socket, &nBlocks, sizeof(int)) < 0)
    {
        perror("Write error ");
        return errno;
    }

    memcpy((char *)prevIV, (const char *)iv, AES_BLOCK_SIZE);

    for (int i = 0; i < nBlocks; i++)
    {

        unsigned char *res = new unsigned char[AES_BLOCK_SIZE];
        encAes(prevIV, res, (unsigned char *)key);
        XOR(res, blocks[i]);
        memcpy((char *)prevIV, (const char *)res, AES_BLOCK_SIZE);

        if (write(socket, res, AES_BLOCK_SIZE) < 0)
        {
            perror("Write error ");
            return errno;
        }
    }
}

int readModeFromConsole(int &mode)
{
    printf("Choose your mode: 1.ECB \n 2.CFB");
    std::cin >> mode;

    return 1;
}

int main()
{
    char *Kkey = new char[AES_BLOCK_SIZE];
    char *entireFile;
    std::ifstream t("text.txt");
    std::stringstream buffer;
    buffer << t.rdbuf();
    entireFile = new char[buffer.str().size()];
    strcpy(entireFile, buffer.str().c_str());

    int n = 0;
    char **blocks;
    blocks = getBlocks(entireFile, n);

    int sockdata;

    if ((sockdata = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error ");
        return errno;
    }

    int enable = 1;
    if (setsockopt(sockdata, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror(":(");

    struct sockaddr_in serv, from;
    bzero(&serv, sizeof(serv));
    bzero(&from, sizeof(from));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(PORT);

    if (bind(sockdata, (struct sockaddr *)&serv, sizeof(struct sockaddr)) == -1)
    {
        perror("error binding stream socket");
        exit(1);
    }

    if (listen(sockdata, 1) == -1)
    {
        perror("Listen error ");
        exit(1);
    }

    int nodeB;
    socklen_t length = sizeof(from);

    nodeB = accept(sockdata, (struct sockaddr *)&from, &length);
    if (nodeB < 0)
    {
        perror("Error ");
        return errno;
    }

    char *key;
    int mode;

    readModeFromConsole(mode);

    if (write(nodeB, &mode, sizeof(int)) < 0)
    {
        perror("Write error ");
        return errno;
    }

    if (!askForKey(Kkey, mode))
    {
        perror("Can't get Kkey from KM");
        exit(-1);
    }

    if (write(nodeB, Kkey, AES_BLOCK_SIZE) < 0)
    {
        perror("Write error ");
        return errno;
    }

    decAes((unsigned char *)Kkey, (unsigned char *)Kkey, (unsigned char *)Kprim);

    if(mode==1)
        encryptECB((const unsigned char **)blocks, n, nodeB, (unsigned char *)Kkey);
    else
        encryptCFB(( unsigned char **)blocks, n, nodeB, (unsigned char *)Kkey);
    close(sockdata);

}