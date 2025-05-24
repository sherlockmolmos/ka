#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#ifdef __cplusplus
//extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

//生成长度为outlen的随机数据并放入out中
void randombytes(uint8_t *out, size_t outlen) ;

#ifdef __cplusplus
//}
#endif

#endif //RANDOMBYTES_H
