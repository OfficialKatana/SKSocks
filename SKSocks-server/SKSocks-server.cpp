// SKSocks-server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"

#ifdef _WIN32
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#else
#include <unistd.h>
#include <arpa/inet.h> //因特网地址结构体相关
#include <sys/socket.h> //socket相关
#include <time.h>  //时间相关
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#endif
#ifndef _WIN32
typedef int SOCKET;
#endif

#define CPPFAILED_INFO "文件: " __FILE__ " 行:" << __LINE__ 
#define SEC_STRDATA(X) X[sizeof(X)-1ULL] = NULL

#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif


class SKServerApp
{
protected:
	typedef int BOOL;
	typedef void* LPVOID;
	typedef unsigned long long UXLONG;
	typedef unsigned char BYTE;
	typedef int32_t INT;
	typedef uint32_t DWORD;

public:
	atomic_int bStatus = FALSE;

public:


};



int main()
{
    std::cout << "Hello World!\n"; 
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
