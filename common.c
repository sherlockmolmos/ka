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




//ʹ��aes128(��ʼ����aes_iv����Կaes_key), ���ܳ���Ϊdata_len��data�����������out
//data���ȱ�����16�ı���������ɴ��뷽��֤
void aes_128_encrypt(const char* aes_key, char* aes_iv, char* data, size_t data_len, char* out) {
    AES_KEY encryptkey;

    AES_set_encrypt_key(aes_key, 128, &encryptkey);

    AES_cbc_encrypt(data, out, data_len, &encryptkey, aes_iv, AES_ENCRYPT);

}

//ʹ��aes128(��ʼ����aes_iv����Կaes_key), ���ܳ���Ϊdata_len��data�����������out
void aes_128_decrypt(const char* aes_key, char* aes_iv, char* data, size_t data_len, char* out) { //data length must multi for 16
    AES_KEY decryptkey;

    AES_set_decrypt_key(aes_key, 128, &decryptkey); //��ʼ�����������ÿ��ʹ�ö��Ὣ��ı䣬���Ը���һ�ݳ������Ա�֤����Ĳ��������ı�

    AES_cbc_encrypt(data, out, data_len, &decryptkey, aes_iv, AES_DECRYPT);
}

//��sockfd��ȡn�ֽ����ݵ�buffer��
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

//��sockfd��ȡָ�������ֽ����ݵ�buffer�У����ݰ�ǰ4���ֽ��������ܳ��ȣ�������ǰ8�ֽڣ�����5-8�ֽ���������ʵ���ȣ�ȥ��Ϊ�˲���16������������ֽڣ���ʣ���Ϊ���ܺ����ݳ���
//���ݰ���aes128���ܣ���ʼ����Ϊiv����ԿΪkey
//������ʵ������outlen����, ���ݽ��ܺ�������ɷ���ֵ���أ����ô�ע��free��
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

//�������һ������Ϊ16-256�ֽڵ����char�����������ݣ����Ȳ���16�ı����Ĳ�����0���
//���ݲ���16�ı�����ĳ��Ⱥ����ݵ���ʵ���Ȼ���Ϊ32λ���η���ǰ8�ֽ�
//������������ݻᱻaes128���ܣ���ʼ����Ϊiv����ԿΪkey
//��ʵ�����ݳ�����random_data_len���أ�����16������ĳ�����random_data_len_to16����
//����������data_plain���أ�����������data_encrypted����
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

//����k+k1+k2��sha256ֵ����out����
void sha256(const unsigned char* k, const unsigned char* k1, const unsigned char* k2, unsigned char* out)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, k, 32);
    SHA256_Update(&sha256, k1, 32);
    SHA256_Update(&sha256, k2, 32);

    SHA256_Final(out, &sha256);
}