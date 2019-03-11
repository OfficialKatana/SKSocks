#pragma once

#define BUFF_SIZE 1024ULL   //设置转发缓冲区
#define TIME_OUT 6000000UL //设置复用IO延时
#define CLIENT_TIME_OUT 6000000UL
#define SERVER_TIME_OUT 5000UL

#define SK_Halo "SK Socket!"

typedef struct SK_Package
{
	uint64_t qwType = 0ULL;
	char lpMemory[BUFF_SIZE] = { 0 };
	uint64_t qwVerify = 0ULL;
	uint64_t qwStatus = 0ULL;
} SK_Pkg, *PSK_Pkg;

#define SK_Conn 1001

