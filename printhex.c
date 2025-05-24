#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

//以16进制打印数据
void printhex(unsigned char *data, size_t len) {
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

//返回16进制形式的字符串
char *stringhex(unsigned char *data, size_t len) {
	char *res = (char *)malloc(len * 3 + 1);

	for (int i = 0; i < len; i++)
    {
        sprintf(res + (i*3), "%02X ", data[i]);
    }

    res[len*3] = 0;

	return res;
}