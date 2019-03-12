// SKSocks-server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <vector>
#include <math.h>

/*

	This file is part of SKSocks.

	SKSocks is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	SKSocks is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with SKSocks.  If not, see <https://www.gnu.org/licenses/>.

*/

/*
	***********************************************************
	* 请勿修改本注释的任何内容。本文件为SK Socks服务端文件。
	* 如果您使用了本文件，请注意本注释禁止被修改。
	* 感谢您的理解。

	* 绑卡实名
	* 软件定制
	* 远控制作
	* 直绑3+2
	* 棋牌站定制
	* 大量出售微信、QQ号
	* 开卡技术
	* 过ZFB人脸识别、V信限额代取
	* DDOS压力测试
	* 线报活动机器人
	* 大量出四件套（真SFZ、咔盾、YH咔、电话咔）
	* 刷QQ会员、QQ钻
	* 不需要实名流量卡出售（7块8GB，10元15GB，20元40GB，30元60GB，40元100G，50元150G，60元200G）
	* 爆卡专用170卡，手机私人实名黑卡
	* WEB安全测试，代提权，代getshell
	* SK团队 专业不止线报
	* 请联系 QQ 1764655874

*/

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
#include<netdb.h>
#ifdef NULL
#undef NULL
#define NULL 0
#endif
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

struct RSAApp
{
	typedef int BOOL;
	typedef void* LPVOID;
	typedef unsigned long long UXLONG;
	typedef unsigned char BYTE;
	typedef int32_t INT;
	typedef uint32_t DWORD;

	unsigned long MIN_LEN = 1000ULL;
	unsigned long MAX_LEN = 2000ULL;
	uint32_t in = 0;
	size_t theVecSize = 0ULL;
	vector<unsigned long> theArray;
	BOOL Initialized = FALSE;
	bool judgeprime(unsigned i) {
		int j;
		for (j = 2U; j <= sqrt(i); j++)
			if (i%j == 0U)
				break;
		if (j > sqrt(i))
			return true;
		return false;
	}
	RSAApp()
	{
		for (auto theMin = MIN_LEN; theMin < MAX_LEN; theMin++)
		{
			if (judgeprime(theMin))
				theArray.push_back(theMin);
		}
		if (theArray.size() > 3ULL)
		{
			Initialized = TRUE;
			theVecSize = theArray.size();
			return;
		}
		// 初始化错误。
		throw - 1;
		Initialized = FALSE;
	}

	struct pairPrime
	{
		uint32_t Prime1 = 0U;
		uint32_t Prime2 = 0U;
		uint32_t PrimeSmall = 0U;
	};

	pairPrime GetPair()
	{
		srand(time(0) + MAX_LEN);
		int thePos = 2 + rand() % (theVecSize - 3UL);
		pairPrime xpair;
		xpair.Prime1 = theArray[thePos];
		xpair.Prime2 = theArray[thePos - 1ULL];
		xpair.PrimeSmall = theArray[thePos - 2ULL];
		return move(xpair);
	}

	struct edm
	{
		uint32_t e = 0U;
		uint32_t d = 0U;
		uint32_t m = 0U;
	};

};

RSAApp theRsaApp;

class SKCommonApp
{
protected:
	typedef int BOOL;
	typedef void* LPVOID;
	typedef unsigned long long UXLONG;
	typedef unsigned char BYTE;
	typedef int32_t INT;
	typedef uint32_t DWORD;

public:
	// 全局定义
	unsigned short theServerRunon = htons(6644);
	BOOL isIPV6 = FALSE;
	unsigned long long qwAuthType = SK_AUTH_NO;
	unsigned char cCryptTypeServer = SK_Crypt_Xor;

protected:
	virtual BOOL CryptData(char* lpData, size_t qwLen, unsigned char cCryptType, string lpKey)
	{
		register auto theKeyLen = lpKey.size();
		switch (cCryptType)
		{
		case SK_Crypt_Xor:
			for (register auto qwFlag = 0ULL; qwFlag < qwLen; qwFlag++)
			{
				lpData[qwFlag] ^= lpKey[qwFlag%theKeyLen];
				lpData[qwFlag] += 0x12;
			}
			return TRUE;
		case SK_Crypt_RSA:
		case SK_Crypt_AES:
		case SK_Crypt_DES:
		case SK_Crypt_RSA_AES:
			break;
		}
		return FALSE;
	}
	virtual BOOL DeCryptData(char* lpData, size_t qwLen, unsigned char cCryptType, string lpKey)
	{
		register auto theKeyLen = lpKey.size();
		switch (cCryptType)
		{
		case SK_Crypt_Xor:
			for (register auto qwFlag = 0ULL; qwFlag < qwLen; qwFlag++)
			{
				lpData[qwFlag] -= 0x12;
				lpData[qwFlag] ^= lpKey[qwFlag%theKeyLen];
			}
			return TRUE;
		case SK_Crypt_RSA:
		case SK_Crypt_AES:
		case SK_Crypt_DES:
		case SK_Crypt_RSA_AES:
			break;
		}
		return FALSE;
	}

	virtual BOOL DoCryptDecrypt(shared_ptr<SK_Package> lpDataPkg, BOOL isCryptData)
	{
		if (!lpDataPkg)return FALSE;
		if (lpDataPkg->qwDataLen > sizeof(lpDataPkg->lpMemory))return FALSE;
		if (isCryptData)
		{
			if (lpDataPkg->qwType == SK_Pkg_Crypted)return TRUE;
			if (!CryptData(lpDataPkg->lpMemory, lpDataPkg->qwDataLen, lpDataPkg->qwCryptType, lpDataPkg->ExtraData))
				return FALSE;
			lpDataPkg->qwType = SK_Pkg_Crypted;
			return TRUE;
		}
		else
		{
			if (lpDataPkg->qwType == SK_Pkg_Decrypted)return TRUE;
			if (!DeCryptData(lpDataPkg->lpMemory, lpDataPkg->qwDataLen, lpDataPkg->qwCryptType, lpDataPkg->ExtraData))
				return FALSE;
			lpDataPkg->qwType = SK_Pkg_Decrypted;
			return TRUE;
		}
		return FALSE;
	}

	virtual string GenKey(int Len)
	{
		string str;
		srand(time(NULL));
		for (auto i = 0; i < Len; i++)
		{
			switch ((rand() % 3))
			{
			case 1:
				str += 'A' + rand() % 26;
				break;
			case 2:
				str += 'a' + rand() % 26;
				break;
			default:
				str += '0' + rand() % 10;
				break;
			}
		}
		return str;
	}

	virtual INT CloseSocket(SOCKET toClose)
	{
#ifdef _WIN32
		auto bRet = closesocket(toClose);
		return bRet;
#else
		return close(toClose);
#endif
	}
public:
	// 成员变量和函数声明
};

class SKServerApp:public SKCommonApp
{
public:
	BOOL bStatus = FALSE;

protected:

	BOOL DoVerify(SOCKET theRem)
	{
		UXLONG Reserve1 = 0ULL;
		if (recv(theRem, (char*)&Reserve1, sizeof(UXLONG), 0) < 0)
		{
#ifdef _DEBUG

			cout << "远程认证出现问题" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return FALSE;
		}
		if (Reserve1 != strlen(SK_Halo))Reserve1 = FALSE;
		INT theLenRecv = send(theRem, (char*)&Reserve1, sizeof(UXLONG), 0);
		if (theLenRecv < 0)return FALSE;
		if (!Reserve1)return FALSE;
		unique_ptr<char>theStr(new char[sizeof(SK_Halo) + 1ULL]);
		if (recv(theRem, &*theStr, sizeof(SK_Halo), 0) < 0)return FALSE;
		if (send(theRem, SK_Halo, sizeof(SK_Halo), 0) < 1)return FALSE;
		(&*theStr)[sizeof(SK_Halo)] = NULL;
		if (string(&*theStr) != string(SK_Halo))return FALSE;
		return TRUE;
	}

	SOCKET GetRealRemoteSock(string IPAddr, unsigned short sPort, BOOL isIPV6)
	{
		// auto strByName = GetHostByName(remHost);

		/*
			* 可以在这里添加禁止内网访问。
			* 提高安全性。
			* 建议添加IP过滤规则，防止恶意利用。
		*/

		int theFlagV6 = AF_INET;
		if (isIPV6)theFlagV6 = AF_INET6;

		/*
		if (strByName == string(""))
		{
			cout << "解析远程域名失败。" << CPPFAILED_INFO << endl;
			return INVALID_SOCKET;
		}
		*/

		SOCKET sockClient = socket(theFlagV6, SOCK_STREAM, 0);// AF_INET ..tcp连接
		if (sockClient == INVALID_SOCKET)
		{
#ifdef _DEBUG

			cout << "创建SOCKET失败。" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return INVALID_SOCKET;
		}

		//初始化连接与端口号
		SOCKADDR_IN addrSrv;

		// auto bRet = inet_pton(theFlagV6, strByName.c_str(), &addrSrv.sin_addr);
		auto bRet = inet_pton(theFlagV6, IPAddr.c_str(), &addrSrv.sin_addr);
#ifdef _DEBUG

		cout << "远程地址是：" << IPAddr << "，端口为：" << long(htons(sPort)) << CPPFAILED_INFO << endl;

#endif // _DEBUG
		addrSrv.sin_family = theFlagV6;
		addrSrv.sin_port = sPort;// 设置端口号
		if (connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)//连接服务器
		{
#ifdef _DEBUG

			cout << "Connect失败。" << "域名为" << IPAddr << "，端口是" << long(htons(sPort)) << CPPFAILED_INFO << endl;

#endif // _DEBUG
			CloseSocket(sockClient);
			return INVALID_SOCKET;
		}

		// OK 返回Socket
		return sockClient;
	}

	BOOL DoFodReal(SOCKET sockCli, SOCKET sockReal, shared_ptr<SK_ConInfo> theSkPkg)
	{
		if (!theSkPkg)
		{
			CloseSocket(sockCli);
			CloseSocket(sockReal);
			return FALSE;
		}
		// char recv_buffer[BUFF_SIZE] = { 0 };
		fd_set fd_read;
		struct timeval time_out;
		time_out.tv_sec = 0;
		time_out.tv_usec = TIME_OUT;
		int ret = 0;

#ifdef _DEBUG
		cout << "开始转发SOCKET数据流。" << CPPFAILED_INFO << endl;
#endif // _DEBUG

		shared_ptr<SK_Package> theData;

		while (bStatus)
		{
			FD_ZERO(&fd_read);
			FD_SET(sockCli, &fd_read);
			FD_SET(sockReal, &fd_read);
			ret = select((sockCli > sockReal ? sockCli : sockReal) + 1, &fd_read, NULL, NULL, &time_out);
			if (-1 == ret)
			{
				break;
			}
			else if (0 == ret)
			{
				continue;
			}
			if (FD_ISSET(sockCli, &fd_read))
			{
				theData.reset(new SK_Package);
				ret = recv(sockCli, (char*)&*theData, sizeof(SK_Package), MSG_WAITALL);
				if (ret > 0)
				{
					if (!theData->qwVerify)break;
					theData->ExtraData[sizeof(theData->ExtraData) - 1ULL] = NULL;
					if (!DoCryptDecrypt(theData, FALSE))
						break;
					ret = send(sockReal, theData->lpMemory, theData->qwDataLen, 0);
					if (ret == -1)
					{
						break;
					}
				}
				else if (ret == 0)
				{
					break;
				}
				else
				{
					break;
				}
			}
			else if (FD_ISSET(sockReal, &fd_read))
			{
				theData.reset(new SK_Package);
				ret = recv(sockReal, theData->lpMemory, sizeof(theData->lpMemory), 0);
				if (ret > 0)
				{
					string RandKey = GenKey(32);
					strcpy_s(theData->ExtraData, RandKey.c_str());
					theData->qwVerify = TRUE;
					theData->qwType = SK_Pkg_Decrypted;
					theData->qwCryptType = cCryptTypeServer;
					theData->qwDataLen = ret;
					if (!DoCryptDecrypt(theData, TRUE))break;
					ret = send(sockCli, (char*)&*theData, sizeof(SK_Package), 0);
					if (ret == -1)
					{
						break;
					}
				}
				else if (ret == 0)
				{
					break;
				}
				else
				{
					break;
				}
			}
		}

		CloseSocket(sockCli);
		CloseSocket(sockReal);
		return TRUE;
	}

	BOOL DoFork(SOCKET sockCli)
	{
		char theBuffer[BUFF_SIZE * 2ULL] = { 0 };
		if (!DoVerify(sockCli))
		{
#ifdef _DEBUG

			cout << "与客户端认证失败。" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			CloseSocket(sockCli);
			return FALSE;
		}

		recv(sockCli, theBuffer, sizeof(SK_ConInfo), MSG_WAITALL);
		SEC_STRDATA(theBuffer);
		shared_ptr<SK_ConInfo> theSkPkg(new SK_ConInfo);
		memcpy(&*theSkPkg, theBuffer, sizeof(SK_ConInfo));
		theSkPkg->theDomain[sizeof(theSkPkg->theDomain) - 1ULL] = NULL;
		BOOL theIPV6 = FALSE;
		if (theSkPkg->cConnIPFlag == SK_Conn_IPV6)theIPV6 = TRUE;
		SOCKET theReal = GetRealRemoteSock(theSkPkg->theDomain, theSkPkg->cConnPort, theIPV6);
		UXLONG lpReserve = 0ULL;
		if (theReal == INVALID_SOCKET)
		{
			send(sockCli, (char*)&lpReserve, sizeof(UXLONG), 0);
			CloseSocket(sockCli);
			return FALSE;
		}
		else
		{
			lpReserve = qwAuthType;
			send(sockCli, (char*)&lpReserve, sizeof(UXLONG), 0);
		}

		if (qwAuthType != SK_AUTH_NO)
		{
			if (!DoVerify(sockCli))
			{
				CloseSocket(sockCli);
				CloseSocket(theReal);
				return FALSE;
			}
		}

		// TODO: 实现验证，懒得实现了。

		thread(&SKServerApp::DoFodReal, this, sockCli, theReal, theSkPkg).detach();

		return TRUE;
	}

	BOOL ServerGetConn()
	{
		int AFNET = AF_INET;
		if (isIPV6)AFNET = AF_INET6;
		SOCKET sockSrv = socket(AFNET, SOCK_STREAM, 0);
		if (sockSrv == INVALID_SOCKET)
		{
			cout << "创建SOCKET失败。" << CPPFAILED_INFO << endl;
			return FALSE;
		}

		SOCKADDR_IN addrSrv;
		addrSrv.sin_addr.s_addr = htonl(INADDR_ANY);
		addrSrv.sin_family = AFNET;
		addrSrv.sin_port = theServerRunon;

		if (::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)// 绑定端口
		{
			cout << "绑定端口失败。" << CPPFAILED_INFO << endl;
			CloseSocket(sockSrv);
			return FALSE;
		}

		listen(sockSrv, 5);

		SOCKADDR_IN addrClient;// 连接上的客户端ip地址
		socklen_t len = sizeof(SOCKADDR);

		cout << "初始化环境成功，开始响应远程请求。" << endl;

		while (bStatus)
		{
			SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);// 接受客户端连接,获取客户端的ip地址

#ifdef _DEBUG

			cout << "收到SOCKET，开始转发数据" << endl;

#endif // DEBUG

			if (sockConn == -1)break;

			thread(&SKServerApp::DoFork, this, sockConn).detach();
		}

		CloseSocket(sockSrv);

		if (bStatus)return TRUE;
		// 失败，返回。
		return FALSE;
	}

public:
	int Main()
	{
		while (bStatus)
		{
			if (ServerGetConn())
				cout << "循环出现异常" << CPPFAILED_INFO << endl;
			else
			{
#ifdef _DEBUG

				break;

#endif // _DEBUG
			}
			cout << "开始新的循环" << CPPFAILED_INFO << endl;
		}
		return 0;
	}

public:
	// TODO: 添加自己的响应函数，或者重载父类函数。
};

// 读写配置文件。
#include <fstream>

int main()
{
	cout << "SK Socks 支持IPV6。可以使用SK Socks穿透防火墙访问内网资源哦~" << endl;
	cout << "仅供学习用途，SK团队不对本工具的稳定性以及使用用途作出任何保证。" << endl;
	cout << "本版本为服务器端。" << endl;
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(1, 1);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		return 0;
	}
#endif
	/**
	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1) {
		WSACleanup();
		return 1;
	}
	*/
	shared_ptr<SKServerApp> _theApp(new SKServerApp);
	_theApp->bStatus = TRUE;
	thread(&SKServerApp::Main, _theApp).join();

#ifdef _WIN32
	WSACleanup();
#endif
	system("pause");
	return 0;
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
