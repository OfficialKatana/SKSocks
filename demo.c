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
 
#define BUFF_SIZE 1024   //设置转发缓冲区
#define TIME_OUT 6000000 //设置复用IO延时
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
 
 
//++++++++++++     sock5协议结构体定义     ++++++++++++++
 
 
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*  
一、客户端认证请求
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     |  1~255   |
    +----+----------+----------+
二、服务端回应认证
    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
三、客户端连接请求(连接目的网络)
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  |   1   |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
四、服务端回应连接
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  |   1   |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
 
//以下为协议结构体定义
 
//一、客户端认证请求
typedef struct client_license_request{
 
    char ver;       // 客户端的协议版本号  0x05:socks5 0x04:socks4
    char nmethods;    // 客户端所支持认证方式的长度
    char methods[255];  //客户端支持的认证方式(可以有255种)
 
}client_license_request;
 
 
//二、服务端回应认证
typedef struct server_license_response{
    char ver;     // 服务端的协议版本号
    char method;  //服务端选择的认证方式
}server_license_response;
 
//三、客户端连接请求
typedef struct client_connect_request{
    char ver;    //客户端协议版本号
    char cmd;    //连接方式
    char rsv;    //保留位0x00
    char type;   //类型
    char addr[4]; //目的服务器ip
    char port[2]; //目的服务器端口
 
 
}client_connect_request;
 
 
//四、服务端回应连接
typedef struct server_connect_response{
    char ver; //版本
    char rep; //连接状态
    char rsv; //保留0x00
    char type; //类型
    char addr[4]; //bind ip
    char port[2]; //bind port
 
 
}server_connect_response;
 
int socketfd_tcp;  //TCP监听套接字
 
 
//转发
int ForwardData( int sock, int real_server_sock )
{
    char recv_buffer[BUFF_SIZE] = { 0 };
    fd_set fd_read;
    struct timeval time_out;
    time_out.tv_sec = 0;
    time_out.tv_usec = TIME_OUT;
    int ret = 0;
    printf("线程%u-开始进行数据转发\n",(int)pthread_self());
    while( 1 )
    {
        FD_ZERO( &fd_read );
        FD_SET( sock, &fd_read );
        FD_SET( real_server_sock, &fd_read );
        ret = select( (sock>real_server_sock?sock:real_server_sock) + 1,&fd_read, NULL, NULL, &time_out);
        if( -1 == ret )
        {
            break;
        }
        else if( 0 == ret )
        {
            continue;
        }
        if( FD_ISSET(sock, &fd_read) )
        {
            memset( recv_buffer, 0, BUFF_SIZE );
            ret = recv( sock, recv_buffer, BUFF_SIZE, 0 );
            if( ret >0 )
            {
                ret = send( real_server_sock, recv_buffer, ret, 0 );
                if( ret == -1 )
                {
                    break;
                }
            }
            else if( ret == 0 )
            {
                break;
            }
            else
            {
                break;
            }
        }
        else if( FD_ISSET(real_server_sock, &fd_read) )
        {
            memset(recv_buffer,0,BUFF_SIZE );
            ret = recv( real_server_sock, recv_buffer, BUFF_SIZE, 0 );
            if( ret > 0 )
            {
                ret = send( sock, recv_buffer, ret, 0 );
                if( ret == -1 )
                {
                    break;
                }
            }
            else if(ret==0)
            {
                break;
            }
            else
            {
                break;
            }
        }
    }
    return 0;
}
 
 
//创建TCP套接字
void tcp_creat()
{
    socketfd_tcp=socket(AF_INET,SOCK_STREAM,0);
    if(socketfd_tcp==-1)
    {
        perror("socketfd_tcp");
        exit(-1);
    }
    
    struct sockaddr_in addr_tcp;
    bzero(&addr_tcp,sizeof(addr_tcp));
    
    addr_tcp.sin_family=AF_INET;
    addr_tcp.sin_port=htons(2018);
    addr_tcp.sin_addr.s_addr=INADDR_ANY;
 
    int re=bind(socketfd_tcp,(struct sockaddr *)&addr_tcp,sizeof(addr_tcp));
    if(re==-1)
    {
        perror("bind");
        exit(-1);
    }
 
    re=listen(socketfd_tcp,100);  //队列长度设为100
    if(re==-1)
    {
        perror("listen");
        exit(-1);
    }
    
}
 
//代理服务器连接目的服务器
int connect_dest_server(client_connect_request * connect_request)
{
    
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd==-1)
    {
        perror("socketfd_tcp");
        return -1;
    }
    struct sockaddr_in sin_server;
    bzero(&sin_server,sizeof(sin_server));
    sin_server.sin_family=AF_INET;
    //目的服务器ip填入结构体
    memcpy(&sin_server.sin_addr,&connect_request->addr,sizeof(connect_request->addr));
    //目的服务器的端口号填入结构体
    memcpy(&sin_server.sin_port,&connect_request->port,sizeof(connect_request->port));
 
    /*2 连接服务器*/
    int re=connect(fd,(struct sockaddr *)&sin_server,sizeof(sin_server));
    if(re==-1)
    {
        // printf("目的服务器连接失败\n");
        return -1;
    }
    // printf("目的服务器连接成功\n");
    return fd;
}
 
 
 
//socks5认证连接
int sock5_license(struct sockaddr_in *addr_client,socklen_t len,int fd)
{
    
 
    //接收认证信息
    char buffer[30]={0};
    read(fd,buffer,sizeof(buffer));
    client_license_request * license_request=(client_license_request *)buffer; 
 
    //验证认证信息
    // printf("客户端版本%d\n",license_request->ver);
    if(license_request->ver!=0x5)
    {
        // printf("协议版本错误\n");
        return 0;
    }
    // printf("客户认证信息通过，回应认证请求\n");
 
    server_license_response license_response;
    license_response.ver=0x5;
    license_response.method=0x0;
    char buff[2]={0};
    memcpy(buff,&license_response,sizeof(buff));
 
    //回应认证信息
    write(fd,buff,sizeof(buff));
 
    // printf("已发送回应请求\n");
 
    //接收连接请求
    bzero(&buffer,sizeof(buffer));
    // printf("等待接收客户连接请求\n");
    read(fd,buffer,sizeof(buffer));
    client_connect_request * connect_request=(client_connect_request *)buffer; 
 
 
    //认证连接请求
    if(connect_request->ver!=0x5)
    {
        
        // printf("连接请求协议版本错误\n");
        return 0;
    }
    if(connect_request->cmd!=0x1)
    {
        // printf("连接请求命令错误(非TCP)\n");
        return 0;
    }
    if(connect_request->type!=0x01)
    {
        // printf("连接请求类型错误(非IPV4)\n");
        return 0;
        
    }
    
    //连接客户端指定的目的地址
    int dest_fd=connect_dest_server(connect_request);
    if(dest_fd==-1)
    {
        return -1;
    }
    
 
    //成功连接则发送回应信息
    //回应连接信息
    char buffer1[10]={0};
    bzero(&buffer,sizeof(buffer1));
 
    
    server_connect_response connect_response;
    bzero(&connect_response,sizeof(connect_response));
    connect_response.ver=0x5;
    connect_response.rep=0x00;  //连接成功标志
    connect_response.rsv=0x00;
    connect_response.type=0x01;
 
    memcpy(buffer1,&connect_response,sizeof(connect_response));//服务端回应数据 设置版本号与结果位，ip与端口号未使用
    write(fd,buffer1,sizeof(buffer1));
 
    // printf("已发送回应请求\n");
 
 
    //全部认证连接建立完成
    //执行转发程序
    ForwardData(fd,dest_fd);
    
 
 
 }
 
 
 
//等待TCP连接，每个客户端分出一条线程，跳转执行socks5认证函数↑↑↑
void * pthread_tcp(void * arg)
{
        printf("线程%u-正在运行\n",(int)pthread_self());
        struct sockaddr_in addr_client;
        socklen_t len=sizeof(addr_client);
        bzero(&addr_client,sizeof(addr_client));
 
        int fd=accept(socketfd_tcp,(struct sockaddr *)&addr_client,&len);
 
 
        pthread_t  pid2;
        pthread_create(&pid2,NULL,pthread_tcp,NULL);
 
        //打印客户端信息
        char ip[20]={0};
        unsigned short port;
        inet_ntop(AF_INET,&addr_client.sin_addr,ip,len);
        port=ntohs(addr_client.sin_port); //转换为本机字节序
        printf("%s：%hu已连接\n",ip,port);
 
        //执行socks5认证
        sock5_license(&addr_client,len,fd);
        printf("线程%u-退出\n",(int)pthread_self());
        return NULL;
 
}
 
 
int main(void)
{
    //创建TCP套接字
    tcp_creat();
    printf("初始化完成等待连接\n");
    while(1)
    {
        printf("主线程%u-正在运行\n",(int)pthread_self());
        pthread_tcp(NULL);
    }
 
}