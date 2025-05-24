#include "common.h"
#include "randombytes.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <errno.h>
#include <openssl/aes.h>
#include <openssl/sha.h>


#ifdef _WIN32

#include <Windows.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <unistd.h>
#endif




//使用aes128(初始向量aes_iv，密钥aes_key), 加密长度为data_len的data并将结果放入out
//data长度必须是16的倍数，这个由传入方保证
void aes_128_encrypt(const char* aes_key, char* aes_iv, char* data, size_t data_len, char* out) {
    AES_KEY encryptkey;

    AES_set_encrypt_key(aes_key, 128, &encryptkey);

    AES_cbc_encrypt(data, out, data_len, &encryptkey, aes_iv, AES_ENCRYPT);

}

//使用aes128(初始向量aes_iv，密钥aes_key), 解密长度为data_len的data并将结果放入out
void aes_128_decrypt(const char* aes_key, char* aes_iv, char* data, size_t data_len, char* out) { //data length must multi for 16
    AES_KEY decryptkey;

    AES_set_decrypt_key(aes_key, 128, &decryptkey); //初始向量这个参数每次使用都会将其改变，所以复制一份出来，以保证传入的参数不被改变

    AES_cbc_encrypt(data, out, data_len, &decryptkey, aes_iv, AES_DECRYPT);
}

//从sockfd读取n字节数据到buffer中
void read_nbytes_from_socket(int sockfd, char* buffer, size_t n) {
    size_t readsize, allreadsize = 0;

    while ((readsize = recv(sockfd, buffer + allreadsize, n - allreadsize, 0)) > 0) {
        allreadsize += readsize;

        if (allreadsize == n) {
            break;
        }
    }

    printf("out\n");
}

//从sockfd读取指定长度字节数据到buffer中，数据包前4个字节是数据总长度（不包括前8字节），第5-8字节是数据真实长度（去除为了补齐16倍数而增添的字节），剩余的为加密后数据长度
//数据包由aes128加密，初始向量为iv，密钥为key
//数据真实长度由outlen返回, 数据解密后的内容由返回值返回（调用处注意free）
char* read_from_socket_with_bytespefix_then_decrept(int sockfd, char* key, char* iv, int* outlen) {
    size_t readsize, allreadsize = 0;
    int datalen = 264;

    char buffer[264] = { 0 }; // 256 + 8

    while ((readsize = recv(sockfd, buffer + allreadsize, datalen - allreadsize, 0)) > 0) {
        //printf("Received: %s\n", buffer);
        allreadsize += readsize;

        if (allreadsize >= 4) {
            memcpy(&datalen, buffer, 4);

            if (datalen == 0) {
                return 0;
            }

            datalen += 8;
        }
        //printf("datelen is %d\n", datalen);

        if (allreadsize == datalen) {
            break;
        }
    }

    memcpy(outlen, buffer + 4, 4);

    char* out = malloc(datalen - 8);

    aes_128_decrypt(key, iv, buffer + 8, datalen - 8, out);

    return out;
}

//随机生成一个长度为16-256字节的随机char类型数组数据，长度不满16的倍数的部分用0填充
//数据补齐16的倍数后的长度和数据的真实长度会作为32位整形放入前8字节
//随机产生的数据会被aes128加密，初始向量为iv，密钥为key
//真实的数据长度由random_data_len返回，补齐16倍数后的长度由random_data_len_to16返回
//数据明文由data_plain返回，数据密文由data_encrypted返回
void random_len_data_encrypt_aes128(int* random_data_len, //true random data len
    int* random_data_len_to16, // 16-256 , 16 multi
    const char* aes_key,
    const char* aes_iv,
    char** data_plain,
    char** data_encrypted) {

    unsigned char templen;
    randombytes(&templen, 1);

    *random_data_len = (int)templen;
    *random_data_len_to16 = *random_data_len + 16 - *random_data_len % 16;

    char* random_data_plain_to16 = (char*)malloc(*random_data_len_to16);
    char* random_data_encryped_lenprefix = (char*)malloc(8 + *random_data_len_to16);

    memset(random_data_plain_to16, 0, *random_data_len_to16);
    randombytes(random_data_plain_to16, *random_data_len);

    memcpy(random_data_encryped_lenprefix, random_data_len_to16, 4);
    memcpy(random_data_encryped_lenprefix + 4, random_data_len, 4);

    aes_128_encrypt(aes_key, aes_iv, random_data_plain_to16, *random_data_len_to16, random_data_encryped_lenprefix + 8);

    *data_plain = random_data_plain_to16;
    *data_encrypted = random_data_encryped_lenprefix;
}

//生成k+k1+k2的sha256值，由out返回
void sha256(const unsigned char* k, const unsigned char* k1, const unsigned char* k2, unsigned char* out)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, k, 32);
    SHA256_Update(&sha256, k1, 32);
    SHA256_Update(&sha256, k2, 32);

    SHA256_Final(out, &sha256);
}