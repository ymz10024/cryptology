#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <ctime>
#include <WinSock2.h>
#include <string>
#include <time.h>
#include <vector>
#include "bigint.h"
#include "gen.h"
#include "aes.h"
#include <cmath>
#include <cstring>
#include "pch.h"
#include "AES.h"
#include "Base64.h"
#pragma comment(lib,"ws2_32.lib")
#define IP "127.0.0.1"
#define MaxBufSize 1024
const int PORT = 8000;
// 表示是否在线，0表示下线，1表示在线
int flag = 0;
using namespace std;
enum Type { chat, csexit ,aes};
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
    strcpy_s(szDataIn, strlen(strSrc.c_str()) + 1, strSrc.c_str());
    //进行PKCS7填充。
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    szDataIn[block_num * BLOCK_SIZE] = '\0';
    //加密后的密文
    char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);
    //进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(g_key, g_iv, 32, 16);
    aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
    string str = base64_encode((unsigned char*)szDataOut,
        block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
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
// 负责接收消息的线程
DWORD WINAPI ClientThread(LPVOID IpParameter)
{
    SOCKET clientsocket = *(SOCKET*)IpParameter;
    int recvLen = 0;
    
    // 接收消息的缓冲区，记得每次要清空
    char recvBuf[MaxBufSize];
    memset(recvBuf, 0, sizeof(recvBuf));
    
    // 当客户端还在线时，持续接收消息
    while (flag) {
        recvLen = recv(clientsocket, recvBuf, MaxBufSize, 0);
        if (recvLen > 0) {
            string s = recvBuf;
            message r = stom(s);
            message m;
            char tmp[32] = { NULL };
            time_t t;
            if (r.type == csexit)
            {
                cout << "----Server is Offline----" << endl;
                cout << "=============Press ENTER to Close Connection=============" << endl;
                t = time(0);
                strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&t));
                m.time = tmp;
                m.type = csexit;
                char sendBuf[MaxBufSize];
                memset(sendBuf, 0, sizeof(sendBuf));
                strcpy_s(sendBuf, mtos(m).c_str());
                send(clientsocket, sendBuf, sizeof(sendBuf), 0);
                flag = 0;
            }
            else if(r.type==chat)
            { 
                cout << r.time << "|" << "Server: " << r.msg;
                string str3 = DecryptionAES(r.msg);
                cout << "解密后:" << str3 << endl;
                
            }
            else if (r.type == aes)
            {
                BigInt xx=BigInt(r.msg);
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
            }
        }
            ::memset(recvBuf, 0, sizeof(recvBuf));
        }
        return 0;
 }


int main() {
    // 加载环境
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "----Client: WSAStartup Eroor----"  << endl;
        return 0;
    }
    else {
        cout << "----Client: WSAStartup Success----" << endl;
    }
    // 创建流式套接字
    SOCKET clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientsocket == INVALID_SOCKET) {
        cout << "----Client: Socket Error----"  << endl;
        return 0;
    }
    else {
        cout << "----Client: Socket Success----" << endl;
    }
    // 连接服务器
    sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(8000);
    serveraddr.sin_addr.S_un.S_addr = inet_addr(IP);
    if (connect(clientsocket, (SOCKADDR*)&serveraddr, sizeof(SOCKADDR))) {
        cout << "----Client: Connect Error----"  << endl;
        return 0;
    }
    else {
        cout << "----Client: Connection Built----" << endl;
        cout << "=============Enter exit to Close Connection=============" << endl;
        flag = 1;
    }
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
    cout << "client端公钥密钥已生成" << endl;
    BigInt ae;
    ae.Random();//生成 作为aes密钥
    cout << "生成AES密钥：" << endl;
    ae.display();
    BigInt c = PowerMode(ae, e, n);
    cout << "经rsa加密后的aes密钥密文为："  << endl;
    c.display();
    string c_ = c.tohex();
    // 接收和发送消息
    char recvBuf[MaxBufSize];
    char sendBuf[MaxBufSize];
    memset(recvBuf, 0, sizeof(recvBuf));
    memset(sendBuf, 0, sizeof(sendBuf));
    
    // 创建线程负责接收消息
    CloseHandle(CreateThread(NULL, 0, ClientThread, (LPVOID)&clientsocket, 0, 0));
    
    
    //BigInt aebi = BigInt(ae);//aebi为大整数类型的aes密钥明文
    //aebi.display();
    //BigInt c = aebi.modPow(e, n);
    
    message m2;
    m2.msg = c_;
    char tmp2[32] = { NULL };
    time_t t1 = time(0);
    strftime(tmp2, sizeof(tmp2), "%Y-%m-%d %H:%M:%S", localtime(&t1));
    m2.time = tmp2;
    m2.type = aes;
    strcpy_s(sendBuf, mtos(m2).c_str());
    send(clientsocket, sendBuf, sizeof(sendBuf), 0);
    memset(sendBuf, 0, sizeof(sendBuf));
    // 当客户端还在线时，随时可以发送消息
    message m;
    cout << "现在可以开始通信..." << endl;
    while (flag) {
        char in[1000];
        cin.getline(in, 1000);
        m.msg = in;
        int len= m.msg.length();
        // 通过时间戳计算发送时间
        char tmp[32] = { NULL };
        time_t t = time(0);
        strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&t));
        m.time = tmp;
        if (m.msg == "exit")
            m.type = csexit;
        else {
            m.type = chat;
            string str2 = EncryptionAES(m.msg);
            m.msg = str2;
            if(len>=1)
                cout << "加密后:" << str2 << endl;
        }
        strcpy_s(sendBuf, mtos(m).c_str());
        send(clientsocket, sendBuf, sizeof(sendBuf), 0);
        memset(sendBuf, 0, sizeof(sendBuf));
        // 输入exit断开连接
        if (m.msg == "exit") {
            cout << "----Client:Connection Closed----" << endl;
            flag = 0;
            break;
        }
    }
    // 关闭监听套接字
    closesocket(clientsocket);
    cout << "----Client:Socket Closed----" << endl;
    //清理环境
    WSACleanup();
    cout << "----Client:WSA Cleaned Up----" << endl;
    system("pause");
    return 0;
}