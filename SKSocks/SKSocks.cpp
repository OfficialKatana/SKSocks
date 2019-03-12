// SKSocks.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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

class SKCommonApp
{
public:
	// 全局定义
	string theRemote = "127.0.0.1";
	unsigned short theRemotePort = htons(6644);
	unsigned short theLocalProxyPort = htons(9966);
	BOOL isIPV6 = FALSE;
	unsigned char cCryptTypeCli = SK_Crypt_Xor;
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
};

class SKProxy :public SKCommonApp
{
public:

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
	//一、客户端认证请求
	typedef struct client_license_request {

		char ver;       // 客户端的协议版本号  0x05:socks5 0x04:socks4
		char nmethods;    // 客户端所支持认证方式的长度
		char methods[255];  //客户端支持的认证方式(可以有255种)

	}client_license_request;


	//二、服务端回应认证
	typedef struct server_license_response {
		char ver;     // 服务端的协议版本号
		char method;  //服务端选择的认证方式
	}server_license_response;

	//三、客户端连接请求
	typedef struct client_connect_request {
		char ver;    //客户端协议版本号
		char cmd;    //连接方式
		char rsv;    //保留位0x00
		char type;   //类型
		char addr[4]; //目的服务器ip
		char port[2]; //目的服务器端口
	}client_connect_request;
	typedef struct client_connect_requestv6 {
		char ver;    //客户端协议版本号
		char cmd;    //连接方式
		char rsv;    //保留位0x00
		char type;   //类型
		short addr[8]; //目的服务器ip
		char port[2]; //目的服务器端口
	}client_connect_requestv6;


	//四、服务端回应连接
	typedef struct server_connect_response {
		char ver; //版本
		char rep; //连接状态
		char rsv; //保留0x00
		char type; //类型
		char addr[4]; //bind ip
		char port[2]; //bind port
	}server_connect_response;
	typedef struct server_connect_responsev6 {
		char ver; //版本
		char rep; //连接状态
		char rsv; //保留0x00
		char type; //类型
		short addr[8]; //bind ip
		char port[2]; //bind port
	}server_connect_responsev6;

protected:
	std::string GetHostByName(string HostName, BOOL isV6 = FALSE)
	{
		struct addrinfo hints;
		struct addrinfo *res;
		int ret = AF_INET;
		struct sockaddr_in *addr;
		char m_ipaddr[16];
		if (isV6)ret = AF_INET6;

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = ret;     /* Allow IPv4 */
		hints.ai_flags = AI_PASSIVE;/* For wildcard IP address */
		hints.ai_protocol = 0;         /* Any protocol */
		hints.ai_socktype = SOCK_STREAM;

		ret = getaddrinfo(HostName.c_str(), NULL, &hints, &res);

		if (ret < 0)
		{
			return string("");
		}
		/*
		struct addrinfo *cur;
		for (cur = res; cur != NULL; cur = cur->ai_next) {
			addr = (struct sockaddr_in *)cur->ai_addr;
			sprintf(m_ipaddr, "%d.%d.%d.%d",
				(*addr).sin_addr.S_un.S_un_b.s_b1,
				(*addr).sin_addr.S_un.S_un_b.s_b2,
				(*addr).sin_addr.S_un.S_un_b.s_b3,
				(*addr).sin_addr.S_un.S_un_b.s_b4);
			printf("%s\n", m_ipaddr);
		}
		*/
		if (!res)
		{
#ifdef _DEBUG

			cout << "域名解析出错，检测到结构指针为空。" << __FILE__ << "行" << __LINE__ << endl;

#endif // _DEBUG
			return string("");
		}
		addr = (struct sockaddr_in *)res->ai_addr;
		sprintf_s(m_ipaddr, "%d.%d.%d.%d",
			(*addr).sin_addr.S_un.S_un_b.s_b1,
			(*addr).sin_addr.S_un.S_un_b.s_b2,
			(*addr).sin_addr.S_un.S_un_b.s_b3,
			(*addr).sin_addr.S_un.S_un_b.s_b4);
#ifdef _DEBUG

		cout << "解析域名IP成功，域名" << HostName << "的IP为" << m_ipaddr << endl;

#endif // _DEBUG
		freeaddrinfo(res);
		return string(m_ipaddr);
	}

	SOCKET ConnToRemote(string remHost, short remport = 80, BOOL isV6 = FALSE)
	{
		// auto strByName = GetHostByName(remHost);

		/*
			* 可以在这里添加禁止内网访问。
			* 提高安全性。
			* 建议添加IP过滤规则，防止恶意利用。
		*/

		int theFlagV6 = AF_INET;
		if (isV6)theFlagV6 = AF_INET6;

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
		auto bRet = inet_pton(theFlagV6, remHost.c_str(), &addrSrv.sin_addr);
#ifdef _DEBUG

		cout << "远程地址是：" << remHost << "，端口为：" << long(htons(remport)) << CPPFAILED_INFO << endl;

#endif // _DEBUG
		addrSrv.sin_family = theFlagV6;
		addrSrv.sin_port = remport;// 设置端口号
		if (connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)//连接服务器
		{
#ifdef _DEBUG

			cout << "Connect失败。" << "域名为" << remHost << "，端口是" << long(htons(remport)) << CPPFAILED_INFO << endl;

#endif // _DEBUG
			CloseSocket(sockClient);
			return INVALID_SOCKET;
		}

		// OK 返回Socket
		return sockClient;
	}

	struct theTargetDef
	{
		BOOL isV6 = FALSE;
		string theRemIP = string("");
		short port = 0;
	};

	BOOL DoVerify(SOCKET theRem)
	{
		UXLONG Reserve1 = strlen(SK_Halo);
		if (send(theRem, (char*)&Reserve1, sizeof(UXLONG), 0) < 0)
		{
#ifdef _DEBUG

			cout << "远程认证出现问题" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return FALSE;
		}
		INT theLenRecv = recv(theRem, (char*)&Reserve1, sizeof(UXLONG), 0);
		if (theLenRecv < 0)return FALSE;
		if (Reserve1 != strlen(SK_Halo))return FALSE;
		unique_ptr<char>theStr(new char[sizeof(SK_Halo) + 1ULL]);
		if (send(theRem, SK_Halo, sizeof(SK_Halo), 0) < 1)return FALSE;
		if (recv(theRem, &*theStr, sizeof(SK_Halo), 0) < 0)return FALSE;
		(&*theStr)[sizeof(SK_Halo)] = NULL;
		if (string(&*theStr) != string(SK_Halo))return FALSE;
		return TRUE;
	}

	BOOL DoAuth(SOCKET sockRem, UXLONG authMethod)
	{

		switch (authMethod)
		{
		case SK_AUTH_IMAGE:
		case SK_AUTH_USER:
		case SK_AUTH_IMAGE_USER:
			break;
		}
		return FALSE;
	}

	BOOL DoFodData(SOCKET sockCli, SOCKET sockRem, shared_ptr<theTargetDef> theTarget)
	{
		if (!theTarget)
		{
			CloseSocket(sockCli);
			CloseSocket(sockRem);
			return FALSE;
		}
		
		if (!DoVerify(sockRem))
		{
#ifdef _DEBUG

			cout << "与服务器认证失败。" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			CloseSocket(sockCli);
			CloseSocket(sockRem);
			return FALSE;
		}
		SK_ConnInfo thePackage;
		thePackage.cConnCryptType = SK_Crypt_Xor;
		thePackage.cConnPort = theTarget->port;
		strcpy_s(thePackage.theDomain, theTarget->theRemIP.c_str());
		if (theTarget->isV6)
			thePackage.cConnIPFlag = SK_Conn_IPV6;
		UXLONG lpReserve = 0ULL;
		send(sockRem, (char*)&thePackage, sizeof(SK_ConInfo), 0);
		recv(sockRem, (char*)&lpReserve, sizeof(UXLONG), 0);
		if (!lpReserve)
		{
			CloseSocket(sockCli);
			CloseSocket(sockRem);
			return FALSE;
		}

		switch (lpReserve)
		{
		case SK_AUTH_NO:
			break;
		case SK_AUTH_IMAGE:
		case SK_AUTH_USER:
		case SK_AUTH_IMAGE_USER:
			if (!DoAuth(sockRem, lpReserve))
			{
				CloseSocket(sockCli);
				CloseSocket(sockRem);
				return FALSE;
			}
			break;
		default:
			CloseSocket(sockCli);
			CloseSocket(sockRem);
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
		shared_ptr< SK_Package> theData;

		while (bStatus)
		{
			FD_ZERO(&fd_read);
			FD_SET(sockCli, &fd_read);
			FD_SET(sockRem, &fd_read);
			ret = select((sockCli > sockRem ? sockCli : sockRem) + 1, &fd_read, NULL, NULL, &time_out);
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
				ret = recv(sockCli, theData->lpMemory, sizeof(theData->lpMemory), 0);
				if (ret > 0)
				{
					string RandKey = GenKey(32);
					strcpy_s(theData->ExtraData, RandKey.c_str());
					theData->qwVerify = TRUE;
					theData->qwType = SK_Pkg_Decrypted;
					theData->qwCryptType = cCryptTypeCli;
					theData->qwDataLen = ret;
					if (!DoCryptDecrypt(theData, TRUE))break;
					ret = send(sockRem, (char*)&*theData, sizeof(SK_Package), 0);
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
			else if (FD_ISSET(sockRem, &fd_read))
			{
				theData.reset(new SK_Package);
				ret = recv(sockRem, (char*)&*theData, sizeof(SK_Package), MSG_WAITALL);
				if (ret > 0)
				{
					if (!theData->qwVerify)break;
					theData->ExtraData[sizeof(theData->ExtraData) - 1ULL] = NULL;
					if (!DoCryptDecrypt(theData, FALSE))
						break;
					ret = send(sockCli, theData->lpMemory, theData->qwDataLen, 0);
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
		CloseSocket(sockRem);
		return TRUE;
	}

	BOOL LocalSocks(SOCKET theSock)
	{
		BOOL isV6 = FALSE;
		BOOL is_Failed = TRUE;
		while (bStatus)
		{
			//接收认证信息
			char buffer[30ULL] = { 0 };
			recv(theSock, buffer, sizeof(buffer), 0);
			SEC_STRDATA(buffer);
			client_license_request * license_request = (client_license_request *)buffer;

			//验证认证信息
			// printf("客户端版本%d\n",license_request->ver);
			if (license_request->ver != 0x5)
			{
				cout << "不是Socks 5。" << CPPFAILED_INFO << endl;
				CloseSocket(theSock);
				break;
			}
			// printf("客户认证信息通过，回应认证请求\n");

			server_license_response license_response;
			license_response.ver = 0x5;
			license_response.method = 0x0;
			char buff[2] = { 0 };
			memcpy(buff, &license_response, sizeof(buff));

			//回应认证信息
			send(theSock, buff, sizeof(buff), 0);

			// printf("已发送回应请求\n");

			//接收连接请求
			memset(buffer, 0, sizeof(buffer));
			// printf("等待接收客户连接请求\n");
			recv(theSock, buffer, sizeof(buffer), 0);
			SEC_STRDATA(buffer);
			client_connect_request * connect_request = (client_connect_request *)buffer;


			//认证连接请求
			if (connect_request->ver != 0x5)
			{
				cout << "本地协议错误。本地请使用 Socks5协议。" << CPPFAILED_INFO << endl;
				// printf("连接请求协议版本错误\n");
				break;
			}
			if (connect_request->cmd != 0x1)
			{
#ifdef _DEBUG

				cout << "不支持非TCP协议！" << CPPFAILED_INFO << endl;

#endif // _DEBUG
				// printf("连接请求命令错误(非TCP)\n");
				break;
			}
			if (connect_request->type != 0x01)
			{
				isV6 = TRUE;
				// cout << "不支持非IPV4的机器！" << CPPFAILED_INFO << endl;
				// printf("连接请求类型错误(非IPV4)\n");
				// break;
			}

			//连接客户端指定的目的地址
			char theRemAddr[64] = { 0 };
			if (isV6)
			{
				client_connect_requestv6 * connect_requestv6 = (client_connect_requestv6 *)buffer;
				sprintf_s(theRemAddr, "%u:%u:%u:%u:%u:%u:%u:%u", (unsigned)(unsigned short)connect_request->addr[0], (unsigned)(unsigned short)connect_request->addr[1],
					(unsigned)(unsigned short)connect_request->addr[2], (unsigned)(unsigned short)connect_request->addr[3],
					(unsigned)(unsigned short)connect_request->addr[4], (unsigned)(unsigned short)connect_request->addr[5],
					(unsigned)(unsigned short)connect_request->addr[6], (unsigned)(unsigned short)connect_request->addr[7]);
			}
			else
				sprintf_s(theRemAddr, "%u.%u.%u.%u", (unsigned)(unsigned char)connect_request->addr[0], (unsigned)(unsigned char)connect_request->addr[1],
				(unsigned)(unsigned char)connect_request->addr[2], (unsigned)(unsigned char)connect_request->addr[3]);

			unsigned short remPort = 0;
			//目的服务器的端口号填入结构体
			if (!isV6)
				memcpy(&remPort, &connect_request->port, sizeof(connect_request->port));
			else
				memcpy(&remPort, ((client_connect_requestv6 *)(connect_request))->port, sizeof(client_connect_requestv6::port));

			// 连接远程加密服务端！
			SOCKET dest_fd = ConnToRemote(theRemote, theRemotePort, isV6);
			// SOCKET dest_fd = ConnToRemote(theRemAddr, remPort, isV6);

			if (dest_fd == INVALID_SOCKET)
			{
				break;
			}


			//成功连接则发送回应信息
			//回应连接信息

			char buffer1[sizeof(server_connect_responsev6)] = { 0 };
			memset(&buffer, 0, sizeof(buffer1));
			if (!isV6)
			{
				server_connect_response connect_response;
				memset(&connect_response, 0, sizeof(connect_response));
				connect_response.ver = 0x5;
				connect_response.rep = 0x00;  //连接成功标志
				connect_response.rsv = 0x00;
				connect_response.type = 0x01;

				memcpy(buffer1, &connect_response, sizeof(connect_response));//服务端回应数据 设置版本号与结果位，ip与端口号未使用
				if (send(theSock, buffer1, sizeof(server_connect_response), 0) < 0)break;
			}
			else
			{
				// IPV6
				server_connect_responsev6 connect_response;
				memset(&connect_response, 0, sizeof(connect_response));
				connect_response.ver = 0x5;
				connect_response.rep = 0x00;  //连接成功标志
				connect_response.rsv = 0x00;
				connect_response.type = 0x01;

				memcpy(buffer1, &connect_response, sizeof(connect_response));//服务端回应数据 设置版本号与结果位，ip与端口号未使用
				if (send(theSock, buffer1, sizeof(server_connect_responsev6), 0) < 0)break;
			}

			// printf("已发送回应请求\n");

			shared_ptr<theTargetDef> _Def(new theTargetDef);
			_Def->isV6 = isV6;
			_Def->theRemIP = theRemAddr;
			_Def->port = remPort;


			//全部认证连接建立完成

			int recvTimeout = PKG_TRANSFER_TIME_OUT;   // 接收超时
			int sendTimeout = PKG_TRANSFER_TIME_OUT;  //发送超时

			setsockopt(theSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
			setsockopt(theSock, SOL_SOCKET, SO_SNDTIMEO, (char *)&sendTimeout, sizeof(int));
			setsockopt(dest_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
			setsockopt(dest_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&sendTimeout, sizeof(int));
			//执行转发程序
			thread(&SKProxy::DoFodData, this, theSock, dest_fd, _Def).detach();
			is_Failed = FALSE;
			break;
		}
		if (is_Failed)
		{
			CloseSocket(theSock);
			return FALSE;
		}
		return TRUE;
	}
	BOOL SetupClientListen()
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
		addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
		addrSrv.sin_family = AFNET;
		addrSrv.sin_port = theLocalProxyPort;

		if (::bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)// 绑定端口
		{
			cout << "绑定端口失败。" << CPPFAILED_INFO << endl;
			CloseSocket(sockSrv);
			return FALSE;
		}

		listen(sockSrv, 5);

		SOCKADDR_IN addrClient;// 连接上的客户端ip地址
		int len = sizeof(SOCKADDR);

		cout << "初始化环境成功，开始转发数据。" << endl;

		while (bStatus)
		{
			SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);// 接受客户端连接,获取客户端的ip地址
#ifdef _DEBUG

			cout << "收到SOCKET，开始转发数据" << endl;

#endif // _DEBUG

			if (sockConn == -1)break;

			thread(&SKProxy::LocalSocks, this, sockConn).detach();
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
			if(SetupClientListen())
				cout<<"循环出现异常" << CPPFAILED_INFO << endl;
			else
			{
#ifdef _DEBUG

				break;

#endif // _DEBUG
			}
			cout<<"开始新的循环" << CPPFAILED_INFO << endl;
		}
		return 0;
	}
public:
		// TODO: 添加自己的响应函数。

};




int main()
{
	cout << "SK Socks 支持IPV6。可以使用SK Socks穿透防火墙访问内网资源哦~" << endl;
	cout << "仅供学习用途，SK团队不对本工具的稳定性以及使用用途作出任何保证。" << endl;
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(1, 1);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		return 0;
	}

	/**
	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1) {
		WSACleanup();
		return 1;
	}
	*/
#endif
	shared_ptr<SKProxy> _theApp(new SKProxy);
	_theApp->bStatus = TRUE;
	thread(&SKProxy::Main, _theApp).join();
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
