// SKSocks.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

// SK 博客网址： https://www.fou.ink/

#include "pch.h"

/*
	***********************************************************
	* 请勿修改本注释的任何内容。本文件为SK Socks客户端文件。
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

/*

	Copyright [2019] [Saurik QQ 1764655874]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

		使用（或者间接引用、参照、复制）本文件（或其中内容）的项目，请务必注明来源，并且必须在显眼位置著名 引用了本文件！

		请务必注明软件原作者以及详细联系方式！

		本软件可以收费售卖，但是您必须说明本软件是可以免费获得的，用户支出的是技术服务费用（智商税）
		Saurik不反对您售卖这个软件（或者关于这个软件的别的产品），如果您想改进这个软件，欢迎和Saurik洽谈。

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
	string theRemote = "127.0.0.1";
	unsigned short theRemotePort = 0;
	unsigned short theLocalProxyPort = 0;
	BOOL isIPV6 = FALSE;
	unsigned char cCryptTypeCli = SK_Crypt_Xor;
	string ClientSession;

	string ClientUsername;
	string ClientPassword;

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

	virtual BOOL DoCryptDecrypt(std::shared_ptr<SK_Package> lpDataPkg, BOOL isCryptData)
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

	virtual string GenHttpHead(string szHost)
	{
		string cstrSendData;
		cstrSendData = "GET /RandomCodeAction.action?" + GenKey(12) + "=0.1 HTTP/1.1\r\n";
		cstrSendData += "Host: " + szHost + "\r\n";
		cstrSendData += "Connection: keep-alive\r\n";
		cstrSendData += "Accept: image/webp,image/*,*/*;q=0.8\r\n";
		cstrSendData += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36\r\n";
		cstrSendData += "Referer:\r\n";
		cstrSendData += "Accept-Encoding: gzip, deflate, sdch\r\n";
		cstrSendData += "Accept-Language: zh-CN,zh;q=0.8\r\n";
		cstrSendData += "Cookie: JSESSIONID=" + GenKey(9) + "\r\n";
		cstrSendData += "\r\n";
		return cstrSendData;
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
	BOOL bStatus = FALSE;
	BOOL Cellular_Free = FALSE;
	string SKRemoteHost;

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
#ifndef _WIN32
			127,0,0,1
#else
			(*addr).sin_addr.s_net,
			(*addr).sin_addr.s_host,
			(*addr).sin_addr.s_lh,
			(*addr).sin_addr.s_impno
#endif
			);
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
		recv(theRem, (char*)&Reserve1, sizeof(UXLONG), MSG_WAITALL);
		if (Reserve1 != strlen(SK_Halo))
		{
#ifdef _DEBUG

			cout << "远程认证出现问题 step1" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return FALSE;
		}
		unique_ptr<char>theStr(new char[sizeof(SK_Halo) + 1ULL]);
		if (send(theRem, SK_Halo, sizeof(SK_Halo), 0) < 1)
		{
#ifdef _DEBUG

			cout << "远程认证出现问题 step2" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return FALSE;
		}
		recv(theRem, &*theStr, sizeof(SK_Halo), MSG_WAITALL);
		(&*theStr)[sizeof(SK_Halo)] = NULL;
		if (string(&*theStr) != string(SK_Halo))
		{
#ifdef _DEBUG

			cout << "远程认证出现问题 step3" << CPPFAILED_INFO << endl;

#endif // _DEBUG
			return FALSE;
		}
		return TRUE;
	}

	BOOL DoAuth(SOCKET sockRem, UXLONG authMethod)
	{
		unique_ptr<SK_Auth_Pkg> theAuthPkg;
		unique_ptr< SK_Session_Pkg> theSession;
		UXLONG theVerify = 0ULL;
		theSession.reset(new SK_Session_Pkg);
		strcpy_s(theSession->lpUserSession, ClientSession.c_str());
		if (send(sockRem, (char*)&*theSession, sizeof(SK_Session_Pkg), 0) < 0)return FALSE;
		recv(sockRem, (char*)&theVerify, sizeof(UXLONG), 0);
		if (theVerify == SK_Auth_Ok)
		{
#ifdef _DEBUG
			cout << "使用Session认证成功！" << CPPFAILED_INFO << endl;
#endif
			return TRUE;
		}
		switch (authMethod)
		{
		case SK_AUTH_USER:
			theAuthPkg.reset(new SK_Auth_Pkg);
			strcpy_s(theAuthPkg->lpUserData, ClientUsername.c_str());
			strcpy_s(theAuthPkg->lpPassword, ClientPassword.c_str());
			if (send(sockRem, (char*)&*theAuthPkg, sizeof(SK_Auth_Pkg), 0) < 0)return FALSE;
			theSession.reset(new SK_Session_Pkg);
			recv(sockRem, (char*)&*theSession, sizeof(SK_Session_Pkg), 0);
			SEC_STRDATA(theSession->lpUserSession);
			if (string(theSession->lpUserSession) == string(""))return FALSE;
			ClientSession = theSession->lpUserSession;
#ifdef _DEBUG
			cout << "尝试用用户名和密码登陆成功！" << CPPFAILED_INFO << endl;
#endif
			return TRUE;
			break;
		case SK_AUTH_IMAGE:
		case SK_AUTH_IMAGE_USER:
#ifdef _DEBUG
			cout << "不支持的校验方法，客户端版本太旧。" << CPPFAILED_INFO << endl;
#endif // _DEBUG

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
				cout << "登陆验证失败！可能是用户名或密码错误！" << endl;
				CloseSocket(sockCli);
				CloseSocket(sockRem);
				return FALSE;
			}
			else
			{
#ifdef _DEBUG
				cout << "登陆成功！开始转发数据！" << CPPFAILED_INFO << endl;
#endif
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
				ret = 1;
				recv(sockRem, (char*)&*theData, sizeof(SK_Package), MSG_WAITALL);
				if (ret > 0)
				{
					if (!theData->qwVerify)break;
					SEC_STRDATA(theData->ExtraData);
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

			if (Cellular_Free)
			{
				// 免流相关
				char lpHttpHeadBuffer[BUFF_SIZE];
				auto szBuffer = GenHttpHead(SKRemoteHost);
				auto qwHeadLen = szBuffer.size();
				if (qwHeadLen > BUFF_SIZE)
				{
#ifdef _DEBUG
					cout << "警告，字节长度过长，将会砍掉大于" << BUFF_SIZE << "字节的长度。" <<
						CPPFAILED_INFO << endl;
#endif // _DEBUG
				}
				memcpy(lpHttpHeadBuffer, szBuffer.c_str(),
					qwHeadLen > BUFF_SIZE ? BUFF_SIZE : (qwHeadLen + 1ULL));
				SEC_STRDATA(lpHttpHeadBuffer);
				if (send(dest_fd, lpHttpHeadBuffer, BUFF_SIZE, 0) < 0)
				{
					CloseSocket(dest_fd);
					break;
				}
#ifdef _DEBUG
				cout << "构建的报文是" << CPPFAILED_INFO << endl;
				cout.write(lpHttpHeadBuffer, BUFF_SIZE);
#endif // _DEBUG
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
		addrSrv.sin_addr.s_addr = htonl(INADDR_ANY);
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
		socklen_t len = sizeof(SOCKADDR);

		cout << "初始化环境成功，开始转发数据。" << endl;

		while (bStatus)
		{
			SOCKET sockConn = accept(sockSrv, (sockaddr *)&addrClient, &len);// 接受客户端连接,获取客户端的ip地址
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

// 读写配置文件。
#include <fstream>
// Linux或Windows 响应Ctrl+C
#include <csignal>
shared_ptr<SKProxy> _theApp;

void sig_handler(int sig)
{
	if (sig == SIGINT)
	{
		if (_theApp)
		{
			_theApp->bStatus = FALSE;
		}
		return;
	}
}

string GetIpByHostName(string theHost, int isV6)
{
	struct addrinfo *answer, hint, *curr;
	char ipstr[0xffULL];
	memset(&hint, 0, sizeof(hint));
	int theFamily = AF_INET;
	if (isV6)theFamily = AF_INET6;
	hint.ai_family = theFamily;
	hint.ai_socktype = SOCK_STREAM;

	int ret = getaddrinfo(theHost.c_str(), NULL, &hint, &answer);
	if (ret != 0) {
		cout << "获取IP地址出错，原因未知。" << CPPFAILED_INFO << endl;
		return string("127.0.0.1");
	}
	if (!answer)
	{
		return string("127.0.0.1");
	}
	for (curr = answer; curr != NULL; curr = curr->ai_next) {
		inet_ntop(theFamily,
			&(((struct sockaddr_in *)(curr->ai_addr))->sin_addr),
			ipstr, 0xffULL);
		cout << "解析的IP地址是：" << ipstr << endl;
	}

	freeaddrinfo(answer);
	return string(ipstr);
}

void Chg_Config(shared_ptr<SKProxy> _App)
{
	ifstream pFile(SK_ClientConfigFile, ios::in);
	unsigned short remoteport = 6644;
	unsigned short localport = 9966;
	string isAutoRun;
	string remoteAddr;
	string uName, passWd;
	unsigned short cCryptType = SK_Crypt_Xor;
	int isV6 = FALSE;
	int isCellular = FALSE;
	string szHost;
	if (pFile)
	{
		pFile >> isAutoRun >> localport >> remoteport >> remoteAddr >> cCryptType >> isV6 >> uName >> passWd
			>> isCellular >> szHost;
		pFile.close();
		if (isAutoRun == string("auto"))
		{
			_App->cCryptTypeCli = cCryptType;
			_App->isIPV6 = isV6;
			_App->theLocalProxyPort = localport;
			_App->theRemotePort = remoteport;
			_App->theRemote = GetIpByHostName(remoteAddr, isV6);
			_App->ClientUsername = uName;
			_App->ClientPassword = passWd;
			_App->SKRemoteHost = szHost;
			_App->Cellular_Free = isCellular;
			return;
		}
	}
	cout << "请输入本地端口（火狐、QQ等使用Socks5的时候使用的端口）" << endl;
	cin >> localport;
	cout << "您输入的本地端口是" << localport << "，请输入远程端口" << endl;
	cin >> remoteport;
	cout << "您输入的远程端口是" << remoteport << "，请输入远程域名或IP地址" << endl;
	cin >> remoteAddr;
	cout << "您输入的远程地址为" << remoteAddr << "，请输入远程机器是否为IPV6，yes即为是" << endl;
	cin >> isAutoRun;
	if (isAutoRun == string("yes"))isV6 = TRUE;
	string theRemIP = GetIpByHostName(remoteAddr, isV6);
	cout << "您的选择为" << isAutoRun << "，请输入是否自动读取配置运行（以后不显示设置消息），输入auto即为是。" << endl;
	cin >> isAutoRun;
	cout << "您的选择是" << isAutoRun << "。请输入用户名，如不需要登陆请直接按回车键。" << endl;
	cin >> uName;
	if (uName != string(""))
	{
		_App->ClientUsername = uName;
		cout << "请输入密码" << endl;
		cin >> passWd;
		_App->ClientPassword = passWd;
	}
	string inputCellularFree;
	cout << "请输入是否需要免流，输入yes为是，别的输入为否。" << endl;
	cin >> inputCellularFree;
	if (inputCellularFree == string("yes"))
	{
		cout << "请输入域名，例如 ad.mi.com" << endl;
		remoteport = 80;
		cin >> szHost;
		isCellular = TRUE;
	}
	if (isAutoRun == string("auto"))
	{
		ofstream pOut(SK_ClientConfigFile, ios::out);
		if (pOut) {
			pOut << isAutoRun << endl;
			pOut << htons(localport) << endl;
			pOut << htons(remoteport) << endl;
			pOut << remoteAddr << endl;
			pOut << cCryptType << endl;
			pOut << isV6 << endl;
			pOut << uName << endl;
			pOut << passWd << endl;
			pOut << isCellular << endl;
			pOut << szHost << endl;
			pOut.close();
		}
	}

	_App->cCryptTypeCli = cCryptType;
	_App->isIPV6 = isV6;
	_App->theLocalProxyPort = htons(localport);
	_App->theRemotePort = htons(remoteport);
	_App->theRemote = theRemIP;
	_App->SKRemoteHost = szHost;
	_App->Cellular_Free = isCellular;
	return;
}

int main()
{
	cout << "SK Socks 支持IPV6。可以使用SK Socks穿透防火墙访问内网资源哦~" << endl;
	cout << "仅供学习用途，SK团队不对本工具的稳定性以及使用用途作出任何保证。" << endl;
	cout << "我们的博客网址为 https://www.fou.ink/ " << endl;
	cout << "本版本为客户端。" << endl;

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
	_theApp.reset(new SKProxy);
	_theApp->bStatus = TRUE;
	Chg_Config(_theApp);
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
