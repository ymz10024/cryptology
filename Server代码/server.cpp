#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//比较新版的vs,会警告我们不要使用一些旧的函数,因为提供更新更安全的函数供使用,这个宏定义就是起屏蔽警告作用,VS下面也有提示
#include <iostream>
#include <WinSock2.h>//socket头文件
#include <string>
#include <time.h>
#include "bigint.h"
#include "gen.h"
#include "pch.h"
#include "AES.h"
#include "Base64.h"
#include <cstring>
#pragma comment(lib,"ws2_32.lib")//载入系统提供的socket动态链接库，加载ws2_32.lib库 
#define IP "127.0.0.1"
#define MaxBufSize 1024//缓冲区大小
const int PORT = 8000;
// 表示是否在线，0表示下线，1表示在线
int flag = 0;
using namespace std;
string key;
enum Type { chat, csexit, aes };
struct message {
    Type type;
    string time;
    string msg;
};
// message类型转换为string类型，字段间以'\n'为分隔符
string mtos(message m) {
    string s;
    if (m.type == 0) {
        s = '0';
    }
    else if (m.type == 1) {
        s = '1';
    }
    else if (m.type == 2) {
        s = '2';
    }
    s.append("\n");
    s.append(m.time);
    s.append("\n");
    s.append(m.msg);
    s.append("\n");
    return s;
}
// string类型转换为message类型，字段间以'\n'为分隔符
message stom(string s) {
    message m;
    if (s[0] == '0') {
        m.type = chat;
    }
    else if (s[0] == '1') {
        m.type = csexit;
    }
    else if (s[0] == '2')
        m.type = aes;
    int i = 2;
    while (s[i] != '\n') {
        i++;
    }
    m.time = s.substr(2, i-2 );
    m.msg = s.substr(i + 1);
    return m;
}
const char g_key[33] = "1234567890AbsEfj987654321HjSCkhe";
const char g_iv[17] = "relylukeaaaadddd";
string EncryptionAES(const string& strSrc) //AES加密
{
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    //strcpy(szDataIn, strSrc.c_str());
    strcpy_s(szDataIn, strlen(strSrc.c_str()) + 1, strSrc.c_str());
    //进行PKCS7填充。
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
    {
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    }
    szDataIn[block_num * BLOCK_SIZE] = '\0';

    //加密后的密文
    char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

    //进行进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(g_key, g_iv, 32, 16);
    aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
    string str = base64_encode((unsigned char*)szDataOut,
        block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    //	delete szDataIn;


    return str;
}
string DecryptionAES(const string& strSrc) //AES解密
{
    string strData = base64_decode(strSrc);
    size_t length = strData.length();
    //密文
    char* szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //明文
    char* szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);

    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(g_key, g_iv, 32, 16);
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] && szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                cout << "去填充失败！解密出错！！" << endl;
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    string strDest(szDataOut);
    delete[] szDataIn;
    delete[] szDataOut;
    return strDest;
}
DWORD WINAPI ServerThread(LPVOID IpParameter) //服务器端处理线程
{
    //新建一个socket用于通信
    SOCKET newsocket = *(SOCKET*)IpParameter;//LPVOID为空指针类型，需要先转成SOCKET类型再引用，即可使用传入的SOCKET
    int recvLen = 0;
    char recvBuf[MaxBufSize];
    memset(recvBuf, 0, sizeof(recvBuf));   
    while (flag) {
        recvLen = recv(newsocket, recvBuf, MaxBufSize, 0);
        
        if (recvLen > 0) {
            string s = recvBuf;
            message r = stom(s);
            if (r.type == csexit)
            {
                cout << "----Client Closed Connection----" << endl;
                cout << "=============Press ENTER to Close Connection=============" << endl;
                flag = 0;
            }
            else if(r.type==chat)
            {
                cout << r.time << "|" << "Client: " << r.msg;
                string str3 = DecryptionAES(r.msg);
                cout << "解密后:" << str3 << endl;
            }
            else if (r.type == aes)
            {
                cout << "收到加密后的aes密钥为：" << r.msg;
                BigInt xx = BigInt(r.msg);
                BigInt p = GeneratePrime();
                BigInt q = GeneratePrime();
                BigInt n = p * q;
                BigInt t = (p - 1) * (q - 1);
                BigInt e, d, y, temp;
                while (1)
                {
                    //产生与t互质的e
                    e.Random();
                    while (!(Gcd(e, t) == 1))
                    {
                        e.Random();
                    }
                    //用扩展欧几里德算法试图求出e模t的乘法逆元
                    temp = ExtendedGcd(e, t, d, y);
                    //e*d模t结果为1，说明d确实是e模t的乘法逆元
                    temp = (e * d) % t;
                    if (temp == 1)
                        break;
                    //否则重新生成e
                }
                BigInt ae;
                ae.Random();
                BigInt m2 = PowerMode(xx, d, n);
                cout << "解密后的明文为：" << endl;
                ae.display();
                cout << "现在可以开始通信..." << endl;
            }
        }
        memset(recvBuf, 0, sizeof(recvBuf));
    }
    return 0;
}

int main() {
    //初始化socket库
    WSADATA wsa;//初始化网络环境
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
    //使用2.2版本的socket，返回值不等于0，说明初始化失败,WSAStartup函数是在程序中初始化并加载Windows网络
    {
        cout << "----Server: WSAStartup Error----" << endl;
        return 0;
    }
    else {
        cout << "----Server: WSAStartup Success----" << endl;
    }
    //创建socket
    SOCKET listensocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//AF_INET使用IPV4地址，SOCK_STREAM使用流传输，IPPROTO_TCP使用TCP协议
    if (listensocket == INVALID_SOCKET) {
        cout << "----Server: Socket Error----" << endl;
        return 0;//套接字创建失败
    }
    else {
        cout << "----Server: Socket Success----" << endl;
    }
    // 一个绑定地址:有IP地址,有端口号,有协议簇 将服务器地址打包在一个结构体里面
    sockaddr_in listenaddr;//sockaddr_in是internet环境下套接字的地址形式
    memset(&listenaddr, 0, sizeof(sockaddr_in));//初始化结构体
    listenaddr.sin_family = AF_INET;//和服务器的socket一样，sin_family表示协议簇，使用IPv4的地址
    listenaddr.sin_port = htons(PORT);//端口号设置为8000
    listenaddr.sin_addr.S_un.S_addr = inet_addr(IP);//服务端地址设置为本地ip地址
    //绑定服务器端socket和打包好的地址
    if (bind(listensocket, (SOCKADDR*)&listenaddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "----Server: Bind Error----" << endl;
        return 0;
    }
    else {
        cout << "----Server: Bind Success to:" << PORT <<"----"<<endl;
        flag = 1;
    }
    // 开启监听
    listen(listensocket, 10);//监听队列长度为10
    cout << "----Server: Start Listening...----" << endl;
    sockaddr_in clientaddr;
    int len = sizeof(sockaddr_in);
    
    // 当服务器在线时，接收客户端的连接请求
    while (flag) {
        // 接收客户端的连接请求并创建新的套接字
        SOCKET newsocket = accept(listensocket, (SOCKADDR*)&clientaddr, &len);
        if (newsocket != INVALID_SOCKET) {
            cout << "----Server:Connection Accepted----" << endl;
            cout << "=============Enter exit to Close Connection=============" << endl;
            //RSA部分
            //产生大素数
            BigInt p = GeneratePrime();
            //16进制形式显示
            BigInt q = GeneratePrime();
            BigInt n = p * q;
            BigInt t = (p - 1) * (q - 1);
            //e为公开钥,d为秘密钥，即e模t的乘法逆元,y用于参与扩展欧几里得运算，存储t模e的乘法逆元
            BigInt e, d, y, temp;
            while (1)
            {
                //产生与t互质的e
                e.Random();
                while (!(Gcd(e, t) == 1))
                {
                    e.Random();
                }
                //用扩展欧几里德算法试图求出e模t的乘法逆元
                temp = ExtendedGcd(e, t, d, y);
                //e*d模t结果为1，说明d确实是e模t的乘法逆元
                temp = (e * d) % t;
                if (temp == 1)
                    break;
                //否则重新生成e
            }
            cout << "server端公钥密钥已生成" << endl;
            BigInt ae;
            ae.Random();//生成 作为aes密钥
            BigInt c = PowerMode(ae, e, n);
            string c_ = c.tohex();
            char recvBuf[MaxBufSize];
            char sendBuf[MaxBufSize];
            memset(recvBuf, 0, sizeof(recvBuf));
            memset(sendBuf, 0, sizeof(sendBuf));
            message m;
            //创建接受链接的线程，不需要句柄所以直接关闭
            CloseHandle(CreateThread(NULL, 0, ServerThread, (LPVOID)&newsocket, 0, 0));

            
            message m2;
            m2.msg = c_;
            char tmp2[32] = { NULL };
            time_t t1 = time(0);
            strftime(tmp2, sizeof(tmp2), "%Y-%m-%d %H:%M:%S", localtime(&t1));
            m2.time = tmp2;
            m2.type = aes;
            strcpy_s(sendBuf, mtos(m2).c_str());
            send(newsocket, sendBuf, sizeof(sendBuf), 0);
            memset(sendBuf, 0, sizeof(sendBuf));
            
            while (flag) {
                char in[1000];
                cin.getline(in, 1000);
                m.msg = in;
                int len = m.msg.length();
                char tmp[32] = { NULL };
                time_t t = time(0);
                strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&t));
                m.time = tmp;
                if (m.msg == "exit")
                    m.type = csexit;
                else
                {
                    m.type = chat;
                    string str2 = EncryptionAES(m.msg);
                    m.msg = str2;
                    if(len>=1)
                        cout << "加密后:" << str2 << endl;
                }
                strcpy_s(sendBuf, mtos(m).c_str());
                send(newsocket, sendBuf, sizeof(sendBuf), 0);
                memset(sendBuf, 0, sizeof(sendBuf));
                if (m.msg=="exit")
                {
                    cout << "----Server:Connection Closed----" << endl;
                    flag = 0;
                    break;
                }
            }
        }
        closesocket(newsocket);
    }
    closesocket(listensocket);
    cout << "----Server:Socket Closed----" << endl;
    WSACleanup();//清理网络环境，释放socket所占的资源
    cout << "----Server:WSA Cleaned Up----" << endl;
    system("pause");
    return 0;
}

