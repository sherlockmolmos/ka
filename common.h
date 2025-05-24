#ifndef COMMON_H
#define COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32


#define SERVER_PK_PATH "server.pk"
#define SERVER_SK_PATH "server.sk"

#define CLIENT_PK_PATH "client.pk"
#define CLIENT_SK_PATH "client.sk"

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <unistd.h>
#include <errno.h>

#define SERVER_PK_PATH "/home/veins/.key/server.pk"
#define SERVER_SK_PATH "/home/veins/.key/server.sk"

#define CLIENT_PK_PATH "/home/veins/.key/client.pk"
#define CLIENT_SK_PATH "/home/veins/.key/client.sk"
#endif

#define ERRORMSG strerror(errno)

#define EVN EV << "\n"
#define EVN1(s1) EV << (s1) << "\n"
#define EVN2(s1, s2) EV << (s1) << (s2) << "\n"
#define EVN3(s1, s2, s3) EV << (s1) << (s2) << (s3) << "\n"
#define EVN4(s1, s2, s3, s4) EV << (s1) << (s2) << (s3) << (s4) << "\n"
#define EVN5(s1, s2, s3, s4, s5) EV << (s1) << (s2) << (s3) << (s4) << (s5) << "\n"

//char *stringhex(unsigned char *data, size_t len);
#define EVHEX(data, len) {char *__str = stringhex((unsigned char *)(data), (len)); EVN1(__str); free(__str);}

#define VFIN(errmsg) throw cRuntimeError((errmsg))
#define VERR(mainmsg) EVN3(mainmsg, " ", ERRORMSG); VFIN((mainmsg))


//使用aes128(初始向量aes_iv，密钥aes_key), 加密长度为data_len的data并将结果放入out
//data长度必须是16的倍数，这个由传入方保证
void aes_128_encrypt(const char *aes_key, const char *aes_iv, char *data, size_t data_len, char *out);

//使用aes128(初始向量aes_iv，密钥aes_key), 解密长度为data_len的data并将结果放入out
void aes_128_decrypt(const char *aes_key, const char *aes_iv, char *data, size_t data_len, char *out);

//从sockfd读取n字节数据到buffer中
void read_nbytes_from_socket(int sockfd, char *buffer, size_t n);

//从sockfd读取指定长度字节数据到buffer中，数据包前4个字节是数据总长度（不包括前8字节），第5-8字节是数据真实长度（去除为了补齐16倍数而增添的字节），剩余的为加密后数据长度
//数据包由aes128加密，初始向量为iv，密钥为key
//数据真实长度由outlen返回, 数据解密后的内容由返回值返回（调用处注意free）
char *read_from_socket_with_bytespefix_then_decrept(int sockfd, char *key, char *iv, int *outlen);

//随机生成一个长度为16-256字节的随机char类型数组数据，长度不满16的倍数的部分用0填充
//数据补齐16的倍数后的长度和数据的真实长度会作为32位整形放入前8字节
//随机产生的数据会被aes128加密，初始向量为iv，密钥为key
//真实的数据长度由random_data_len返回，补齐16倍数后的长度由random_data_len_to16返回
//数据明文由data_plain返回，数据密文由data_encrypted返回
void random_len_data_encrypt_aes128(int *random_data_len, //true random data len
                                    int *random_data_len_to16, // 16-256 , 16 multi
                                    const char *aes_key,
                                    const char *aes_iv,
                                    char **data_plain,
                                    char **data_encrypted);

//生成k+k1+k2的sha256值，由out返回
void sha256(const unsigned char *k, const unsigned char *k1, const unsigned char *k2, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif //COMMON_H
