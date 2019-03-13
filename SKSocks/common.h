#pragma once

// SK 博客网址： https://www.fou.ink/

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

/*
	***********************************************************
	* 请勿修改本文件的任何内容。本文件为SK Socks定义文件。
	* 如果您使用了本文件，请注意本文件禁止被修改。
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

#ifndef _WIN32
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)
#define SOCKADDR sockaddr
#define SOCKADDR_IN sockaddr_in
#define strcpy_s strcpy
#define sprintf_s sprintf
#endif

#define BUFF_SIZE 500ULL   //设置转发缓冲区
#define TIME_OUT 6000000UL //设置复用IO延时
#define CLIENT_TIME_OUT 6000000UL
#define PKG_TRANSFER_TIME_OUT 5000UL

#define SK_Halo "SK Socket!"

#define SK_Conn 1001
#define SK_ServerConfigFile "server.hpp"
#define SK_ClientConfigFile "client.hpp"
#define SK_ServerUserFile "ufile.txt"

#define SK_Conn_IPV6 0x1
#define SK_Conn_IPV4 0x2 // IPV4
#define SK_Conn_LocalIPV4 0x4 // 本机IPV4，可以访问广域网IPV6
#define SK_Crypt_Xor 0x1 // 最快
#define SK_Crypt_RSA 0x2 // RSA
#define SK_Crypt_AES 0x4
#define SK_Crypt_DES 0x8
#define SK_Crypt_RSA_AES 0x10 // RSA加密AES密匙，推荐，安全。
#define SK_AUTH_NO 0x1ULL
#define SK_AUTH_IMAGE 0x2ULL // 图片验证码
#define SK_AUTH_USER 0x4ULL // 用户名密码
#define SK_AUTH_IMAGE_USER 0x8ULL // 用户名密码以及图片验证码（推荐）

typedef struct SK_ConnInfo
{
	typedef unsigned char CBYTE;
	CBYTE cConnIPFlag = SK_Conn_IPV4;
	CBYTE cConnCryptType = SK_Crypt_Xor;
	CBYTE cConnAuthType = SK_AUTH_NO;
	CBYTE cConnReserve = 0; //保留
	unsigned short cConnPort = 0;
	char theDomain[0xff] = { 0 };
}SK_ConInfo, *PSK_ConInfo;

#define SK_Pkg_Crypted 1ULL
#define SK_Pkg_Decrypted 0ULL
typedef struct SK_Package
{
	typedef unsigned long long uint64_t;
	typedef unsigned char CBYTE;
	CBYTE qwType = SK_Pkg_Decrypted;
	CBYTE qwCryptType = SK_Crypt_Xor;
	char lpMemory[BUFF_SIZE] = { 0 };
	char ExtraData[64ULL] = { 0 };
	uint64_t qwVerify = 0ULL;
	uint64_t qwDataLen = 0ULL;
	uint64_t qwReserve = 0ULL;
} SK_Pkg, *PSK_Pkg;

#define SK_Auth_Session 1ULL
#define SK_Auth_First 2ULL
#define SK_Auth_Once 3ULL
#define SK_Auth_Always 4ULL
#define SK_Auth_Captcha 5ULL
#define SK_Auth_Failed 6ULL
#define SK_Auth_Success 7ULL
#define SK_Auth_Success_And_GetSession 8ULL
#define SK_Auth_Success_And_GetToken 9ULL
#define SK_Auth_UserNamePwd 10ULL
#define SK_Auth_IP_Restrict 11ULL
#define SK_Auth_Master 12ULL
#define SK_Auth_GetSession 13ULL
#define SK_Auth_Version "1.0"

#define SK_Auth_Incorrect 0ULL
#define SK_Auth_Ok 1ULL
#define SK_Auth_Need_Captcha 2ULL
#define SK_Auth_Need_User 3ULL
#define SK_Auth_Need_User_And_Captcha 4ULL

#define SK_Session_Key_Len 16ULL
#define SK_Auth_UNAME_PWD_Len 32ULL

typedef struct SK_Auth_Session_Pkg
{
	char lpUserSession[SK_Session_Key_Len] = { 0 };
}SK_Session_Pkg, *PSK_Session_Pkg;

typedef struct SK_OAuth_Pkg
{
	typedef unsigned long long UINT64;
	char lpUserData[SK_Auth_UNAME_PWD_Len] = { 0 };
	char lpPassword[SK_Auth_UNAME_PWD_Len] = { 0 };
	UINT64 lpReserve = 0ULL;
}SK_Auth_Pkg, *PSK_Auth_Pkg;


