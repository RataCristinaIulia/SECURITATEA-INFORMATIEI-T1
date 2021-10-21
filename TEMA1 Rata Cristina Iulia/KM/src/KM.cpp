#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/opensslconf.h>
#include "openssl/aes.h"
#include <openssl/rand.h>
#include <pthread.h>
#include <iostream>

#define PORT 8080
#define ECB_MODE 1
#define CFB_MODE 0

#define Kprim (unsigned char *)"1234567abcdef123"

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

int generateKey(unsigned char *K)
{
    RAND_bytes(K, 16);
}

void *treatClient(void *arg)
{
    int socket = *((int *)arg);

    unsigned char *K = new unsigned char[AES_BLOCK_SIZE];
    generateKey(K);

    encAes(K, K, Kprim);

    if (write(socket, K, AES_BLOCK_SIZE) < 0)
    {
        perror("[KM]: Write error ");
        exit(1);
    }
}

int main()
{
    struct sockaddr_in servaddr, from;
    int sockkm;

    if ((sockkm = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error ");
        return errno;
    }

    bzero(&servaddr, sizeof(servaddr));
    bzero(&from, sizeof(from));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockkm, (struct sockaddr *)&servaddr, sizeof(struct sockaddr)) == -1)
    {
        perror("Bind error ");
        return errno;
    }

    if (listen(sockkm, 10) == -1)
    {
        perror("Listen error ");
        return errno;
    }

    while (1)
    {
        int client;
        socklen_t len = sizeof(from);

        client = accept(sockkm, (sockaddr *)&from, &len);
        if (client < 0)
        {
            //perror("Error ");
            continue;
        }

        int *t = new int;
        *t = client;

        int a;
        pthread_create((pthread_t *)&a, NULL, &treatClient, t);
    }
}