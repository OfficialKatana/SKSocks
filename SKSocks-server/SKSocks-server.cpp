// SKSocks-server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

// SK 博客网址： https://www.die.lu/

#include "pch.h"
#include <vector>
#include <math.h>

/*
	***********************************************************
	* 本文件为SK Socks客户端文件。
	* 请慎将此源码直接用于商业用途，由于商业用途造成的一切法律后果本人概不负责。
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
	* 请联系 QQ 2737996094

*/

/*

	Copyright [2019] [Saurik QQ 2737996094]

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
	unsigned short theServerRunon = 0;
	BOOL isIPV6 = FALSE;
	unsigned long long qwAuthType = SK_AUTH_NO;
	unsigned char cCryptTypeServer = SK_Crypt_Xor;
	string ServerSession;
	map<string, string> userMap;

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

	BOOL isIPLAN(const string ipstring)
	{
		istringstream st(ipstring);
		int ip[2];
		for (int i = 0; i < 2; i++)
		{
			string temp;
			getline(st, temp, '.');
			istringstream a(temp);
			a >> ip[i];
		}
		if ((ip[0] == 10) || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168))
			return TRUE;
		else return FALSE;
	}

public:
	atomic_ulong theThreadCount = { 0UL };
	BOOL bStatus = FALSE;
protected:

	typedef function <BOOL(SOCKET)> theCliFork;
	timed_mutex theMutex;
	typedef struct
	{
		theCliFork theThread;
		SOCKET theSock;
		chrono::system_clock::time_point theAddupTime;
	}theFuncPkg, *PtheFuncPkg;
	list<theFuncPkg> theThreadList;
	BOOL addToThreadPool(theCliFork thePkg, SOCKET theConn)
	{
		theFuncPkg theThreadPack;
		theThreadPack.theSock = theConn;
		theThreadPack.theThread = thePkg;
		theThreadPack.theAddupTime = chrono::system_clock::now();
		if (!theMutex.try_lock_for(chrono::milliseconds(PKG_TRANSFER_TIME_OUT)))
			return FALSE;
		auto theThrWaitCount = theThreadList.size();
		if (theThrWaitCount > MAX_THREAD_COUNT)goto T_ADD_FAILED;
#ifdef _DEBUG
		cout << "当前容器线程数量：" << theThrWaitCount << CPPFAILED_INFO << endl;
#endif // _DEBUG
		theThreadList.push_back(theThreadPack);
		theMutex.unlock();
		if (theThreadCount < MAX_RUNNING_THREAD)
		{
			thread(&SKCommonApp::doThreadPoolFork, this).detach();
			theThreadCount++;
		}

#ifdef _DEBUG
		cout << "当前运行中的线程数量：" << theThreadCount << CPPFAILED_INFO << endl;
#endif // _DEBUG

		goto T_ADD_OK;
	T_ADD_FAILED:
		theMutex.unlock();
		return FALSE;
	T_ADD_OK:
		return TRUE;
	}

	BOOL doThreadPoolFork()
	{
		while (bStatus)
		{
			if (!theMutex.try_lock_for(chrono::milliseconds(PKG_TRANSFER_TIME_OUT)))
			{
				theThreadCount--;
				return FALSE;
			}
			if (theThreadList.empty())
			{
				theMutex.unlock();
				break;
			}
			if (chrono::system_clock::now() - theThreadList.front().theAddupTime > chrono::milliseconds(PKG_TRANSFER_TIME_OUT))
			{
#ifdef _DEBUG
				cout << "线程过多，正在清理当中。。。" << CPPFAILED_INFO << endl;
#endif // _DEBUG
				for (auto theListItor = theThreadList.begin(); theListItor != theThreadList.end(); theListItor++)
				{
					CloseSocket(theListItor->theSock);
				}
				theThreadList.clear();
				theMutex.unlock();
				theThreadCount--;
				return TRUE;
			}
			auto theWork = theThreadList.back();
			theThreadList.pop_back();
			theMutex.unlock();
			theWork.theThread(theWork.theSock);
		}
#ifdef _DEBUG
		cout << "线程退出，当前线程数量为" << theThreadCount << CPPFAILED_INFO << endl;
#endif // _DEBUG

		theThreadCount--;
		return TRUE;
	}

public:
	// 成员变量和函数声明
};

class SKServerApp:public SKCommonApp
{
public:
	BOOL Cellular_Free = FALSE;
public:
	BOOL bStatus = FALSE;

protected:

	BOOL DoVerify(SOCKET theRem)
	{
		UXLONG Reserve1 = 0ULL;
		recv(theRem, (char*)&Reserve1, sizeof(UXLONG), MSG_WAITALL);
		if (Reserve1 != strlen(SK_Halo))Reserve1 = FALSE;
		INT theLenRecv = send(theRem, (char*)&Reserve1, sizeof(UXLONG), 0);
		if (theLenRecv < 0)return FALSE;
		if (!Reserve1)return FALSE;
		unique_ptr<char>theStr(new char[sizeof(SK_Halo) + 1ULL]);
		recv(theRem, &*theStr, sizeof(SK_Halo), MSG_WAITALL);
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
		if (isIPV6)
			if (isIPLAN(IPAddr))
			{
#ifdef _DEBUG
				cout << "禁止访问内网资源！" << CPPFAILED_INFO << endl;
#endif // _DEBUG
				return INVALID_SOCKET;
			}

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

	BOOL ChkUserPwd(string UNAME, string PWD)
	{
		auto mItor = userMap.find(UNAME);
		if (mItor == userMap.end())return FALSE;
		if (mItor->second != PWD)return FALSE;
		return TRUE;
	}
public:

	void AddUser(string UNAME, string PWD)
	{
		// 有空建议使用 非可逆加密 加密一下密码。
		userMap[UNAME] = PWD;
	}

	BOOL RemoveUser(string UNAME)
	{
		// 建议加锁。懒得加了。
		// 推荐数据库实现，不过数据库实现的话性能就很差了。
		// 如果用数据库实现，建议把频繁连接的用户缓存到map容器里面。
		auto mItor = userMap.find(UNAME);
		if (mItor == userMap.end())return FALSE;
		userMap.erase(mItor);
		return TRUE;
	}
protected:

	BOOL DoAuth(SOCKET sockCli, UXLONG qwMethod)
	{
		unique_ptr<SK_Auth_Pkg> theAuthPkg;
		unique_ptr< SK_Session_Pkg> theSession;
		UXLONG lpReserve = SK_Auth_Incorrect;
		theSession.reset(new SK_Session_Pkg);
		recv(sockCli, (char*)&*theSession, sizeof(SK_Session_Pkg), 0);
		SEC_STRDATA(theSession->lpUserSession);
		if (string(theSession->lpUserSession) == ServerSession)
		{
			lpReserve = SK_Auth_Ok;
			if (send(sockCli, (char*)&lpReserve, sizeof(UXLONG), 0) < 0)return FALSE;
			return TRUE;
		}
		switch (qwMethod)
		{
		case SK_AUTH_USER:
			if (send(sockCli, (char*)&lpReserve, sizeof(UXLONG), 0) < 0)return FALSE;
			theAuthPkg.reset(new SK_Auth_Pkg);
			recv(sockCli, (char*)&*theAuthPkg, sizeof(SK_Auth_Pkg), 0);
			SEC_STRDATA(theAuthPkg->lpUserData);
			SEC_STRDATA(theAuthPkg->lpPassword);
			theSession.reset(new SK_Session_Pkg);
			if (!ChkUserPwd(theAuthPkg->lpUserData, theAuthPkg->lpPassword))
			{
				strcpy_s(theSession->lpUserSession, "");
				send(sockCli, (char*)&*theSession, sizeof(SK_Session_Pkg), 0);
				return FALSE;
			}
			strcpy_s(theSession->lpUserSession, ServerSession.c_str());
			if (send(sockCli, (char*)&*theSession, sizeof(SK_Session_Pkg), 0) < 0)return FALSE;
			return TRUE;
			break;
		default:
			break;
		}
		return FALSE;
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
				ret = 1;
				recv(sockCli, (char*)&*theData, sizeof(SK_Package), MSG_WAITALL);
				if (ret > 0)
				{
					if (!theData->qwVerify)break;
					SEC_STRDATA(theData->ExtraData);
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

		if (Cellular_Free)
		{
			// 免流相关
			BOOL bRet = recv(sockCli, theBuffer, BUFF_SIZE, MSG_WAITALL);
			if (bRet == -1)
			{
#ifdef _DEBUG
				cout << "接收客户端http报文失败。" << CPPFAILED_INFO << endl;
#endif // _DEBUG
				CloseSocket(sockCli);
				return FALSE;
			}
#ifdef _DEBUG
			cout << "收到http免流报文，内容是" << CPPFAILED_INFO << endl;
			SEC_STRDATA(theBuffer);
			cout.write(theBuffer, sizeof(theBuffer));
#endif // _DEBUG
		}

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
		SEC_STRDATA(theSkPkg->theDomain);
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
			if (!DoAuth(sockCli, qwAuthType))
			{
#ifdef _DEBUG
				cout << "有一个用户登陆失败，如果频繁看见这个消息，请小心用户名和密码爆破。" << CPPFAILED_INFO << endl;
#endif // _DEBUG
				CloseSocket(sockCli);
				CloseSocket(theReal);
				return FALSE;
			}
		}

		// TODO: 实现验证，懒得实现了。


		int recvTimeout = PKG_TRANSFER_TIME_OUT;   // 接收超时
		int sendTimeout = PKG_TRANSFER_TIME_OUT;  //发送超时

		setsockopt(sockCli, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
		setsockopt(sockCli, SOL_SOCKET, SO_SNDTIMEO, (char *)&sendTimeout, sizeof(int));
		setsockopt(theReal, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
		setsockopt(theReal, SOL_SOCKET, SO_SNDTIMEO, (char *)&sendTimeout, sizeof(int));

		thread(&SKServerApp::DoFodReal, this, sockCli, theReal, theSkPkg).detach();

		return TRUE;
	}
public:
	SOCKET sockSrv = NULL;
	BOOL onStop(LPVOID pInstance)
	{
		if (pInstance != this)
		{
			return ((SKServerApp*)pInstance)->onStop(pInstance);
		}
		if (!sockSrv)return FALSE;
		CloseSocket(sockSrv);
		BOOL bDontLinger = FALSE;
		setsockopt(sockSrv, SOL_SOCKET, SO_DONTLINGER, (const char*)&bDontLinger, sizeof(BOOL));
		return TRUE;
	}
protected:
	BOOL ServerGetConn()
	{
		int AFNET = AF_INET;
		if (isIPV6)AFNET = AF_INET6;
		sockSrv = socket(AFNET, SOCK_STREAM, 0);
		// 最长不超过 SK_Session_Key_Len （定义为16ULL，就是15字节长）
		ServerSession = GenKey(8);
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

		
		chrono::system_clock::time_point theTime = chrono::system_clock::now();

		while (bStatus)
		{
			if (chrono::system_clock::now() - theTime > SK_VALID_PERIOD)
			{
				ServerSession = GenKey(8);
#ifdef _DEBUG
				cout << "保持的状态强制过期，正在更换Session保证用户登陆安全。" << CPPFAILED_INFO << endl;
#endif // _DEBUG

				theTime = chrono::system_clock::now();
			}
		
			SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);// 接受客户端连接,获取客户端的ip地址

#ifdef _DEBUG

			cout << "收到SOCKET，开始转发数据" << endl;

#endif // DEBUG

			if (sockConn == -1)break;

			thread(&SKServerApp::DoFork, this, sockConn).detach();
		}

		CloseSocket(sockSrv);
		BOOL bDontLinger = FALSE;
		setsockopt(sockSrv, SOL_SOCKET, SO_DONTLINGER, (const char*)&bDontLinger, sizeof(BOOL));

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
// Linux或Windows 响应Ctrl+C
#include <csignal>
shared_ptr<SKServerApp> _theApp;

void sig_handler(int sig)
{
	if (sig == SIGINT)
	{
		if (_theApp)
		{
			_theApp->bStatus = FALSE;
			_theApp->onStop(&*_theApp);
		}
		return;
	}
}

void Chg_Config(shared_ptr<SKServerApp> _App)
{
	ifstream pFile(SK_ServerConfigFile, ios::in);
	unsigned short port = htons(6644);
	string isAutoRun;
	unsigned long long qwAuthType = SK_AUTH_NO;
	unsigned short cCryptType = SK_Crypt_Xor;
	int isV6 = FALSE;
	int isCellularFree = FALSE;
	if (pFile)
	{
		pFile >> isAutoRun >> port >> qwAuthType >> cCryptType >> isV6
			>> isCellularFree;
		pFile.close();
		if (isAutoRun == string("auto"))
		{
			_App->theServerRunon = port;
			_App->cCryptTypeServer = cCryptType;
			_App->isIPV6 = isV6;
			_App->qwAuthType = qwAuthType;
			_App->Cellular_Free = isCellularFree;
			cout << "当前信息：端口" << htons(port) << "，登陆类型" << qwAuthType << "，IPv6：" << isV6 << endl;
			cout << "免流配置：" << isCellularFree << endl;
			if (qwAuthType == SK_AUTH_USER)
			{
				ifstream uFile(SK_ServerUserFile, ios::in);
				if (uFile)
				{
					string szUser, szPwd;
					while (uFile.peek() != EOF)
					{
						uFile >> szUser >> szPwd;
						_App->AddUser(szUser, szPwd);
					}
					uFile.close();
				}
			}
			return;
		}
	}
	cout << "请输入要绑定的端口。。。" << endl;
	cin >> port;
	cout << "您输入的端口是" << port << "，请输入是否自动运行，输入auto为自动运行(以后不提示直接运行)，其它为不自动运行。" << endl;
	cin >> isAutoRun;
	cout << "请输入是否为IPV6，yes即为是。" << endl;
	string buffer_IPV6;
	cin >> buffer_IPV6;
	if (buffer_IPV6 == string("yes"))
		isV6 = TRUE;
	cout << "请输入是否需要免流？需要请输入yes，不需要请输入任意字符。" << endl;
	cin >> buffer_IPV6;
	if (buffer_IPV6 == string("yes"))
	{
		isCellularFree = TRUE;
		port = 80;
		cout << "您选择了需要免流。" << endl;
	}

	cout << "请输入是否需要用户登陆，用户名和密码列表在" SK_ServerUserFile "里面，输入yes即为需要。" << endl;
	cout << "用户名密码格式为：用户名 （空格） 密码，一行一个数据，用户名和密码不能有空格。如有需要可以自己定制用户名密码验证。" << endl;
	cout << "注意：用户名和密码的长度均不能超过" << (SK_Auth_UNAME_PWD_Len - 1ULL) << "个字符。" << endl;
	cin >> buffer_IPV6;
	if (buffer_IPV6 == string("yes"))
	{
		qwAuthType = SK_AUTH_USER;
		ifstream uFile(SK_ServerUserFile, ios::in);
		unsigned long long qwCount = 0ULL;
		if (uFile)
		{
			string szUser, szPwd;
			while (uFile.peek() != EOF)
			{
				uFile >> szUser >> szPwd;
				if (szUser == string("") || szPwd == string(""))
				{
					cout << "WARNING: 读取的用户名或密码为空！已经跳过。" << CPPFAILED_INFO << endl;
					continue;
				}
				_App->AddUser(szUser, szPwd);
				qwCount++;
			}
			cout << "读取了" << qwCount << "个用户" << endl;
			uFile.close();
		}
		else
		{
			cout << "打开用户数据文件操作失败，请检查权限。" << endl;
		}
	}

	if (isAutoRun == string("auto"))
	{
		ofstream pOut(SK_ServerConfigFile, ios::out);
		if (pOut) {
			pOut << isAutoRun << endl;
			pOut << htons(port) << endl;
			pOut << qwAuthType << endl;
			pOut << cCryptType << endl;
			pOut << isV6 << endl;
			pOut << isCellularFree << endl;
			pOut.close();
		}
	}

	_App->theServerRunon = htons(port);
	_App->cCryptTypeServer = cCryptType;
	_App->isIPV6 = isV6;
	_App->qwAuthType = qwAuthType;
	_App->Cellular_Free = isCellularFree;

	return;
}



int main()
{
	cout << "SK Socks 支持IPV6。可以使用SK Socks穿透防火墙访问内网资源哦~" << endl;
	cout << "仅供学习用途，SK团队不对本工具的稳定性以及使用用途作出任何保证。" << endl;
	cout << "本版本为服务器端。" << endl;
	cout << "我们的博客网址为 https://www.die.lu/ " << endl;
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(1, 1);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		return 0;
	}
#else
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigprocmask(SIG_BLOCK, &set, NULL);
#endif
	/**
	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1) {
		WSACleanup();
		return 1;
	}
	*/
	_theApp.reset(new SKServerApp);
	signal(SIGINT, sig_handler);
	_theApp->bStatus = TRUE;
	Chg_Config(_theApp);
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
