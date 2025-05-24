#ifndef PRINTHEX_H
#define PRINTHEX_H

#ifdef __cplusplus
extern "C" {
#endif

//以16进制打印数据
void printhex(unsigned char *data, size_t len);

//返回16进制形式的字符串
char *stringhex(unsigned char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif //PRINTHEX_H
