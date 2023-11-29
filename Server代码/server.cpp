#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//�Ƚ��°��vs,�ᾯ�����ǲ�Ҫʹ��һЩ�ɵĺ���,��Ϊ�ṩ���¸���ȫ�ĺ�����ʹ��,����궨����������ξ�������,VS����Ҳ����ʾ
#include <iostream>
#include <WinSock2.h>//socketͷ�ļ�
#include <string>
#include <time.h>
#include "bigint.h"
#include "gen.h"
#include "pch.h"
#include "AES.h"
#include "Base64.h"
#include <cstring>
#pragma comment(lib,"ws2_32.lib")//����ϵͳ�ṩ��socket��̬���ӿ⣬����ws2_32.lib�� 
#define IP "127.0.0.1"
#define MaxBufSize 1024//��������С
const int PORT = 8000;
// ��ʾ�Ƿ����ߣ�0��ʾ���ߣ�1��ʾ����
int flag = 0;
using namespace std;
string key;
enum Type { chat, csexit, aes };
struct message {
    Type type;
    string time;
    string msg;
};
// message����ת��Ϊstring���ͣ��ֶμ���'\n'Ϊ�ָ���
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
// string����ת��Ϊmessage���ͣ��ֶμ���'\n'Ϊ�ָ���
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
string EncryptionAES(const string& strSrc) //AES����
{
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //����
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    //strcpy(szDataIn, strSrc.c_str());
    strcpy_s(szDataIn, strlen(strSrc.c_str()) + 1, strSrc.c_str());
    //����PKCS7��䡣
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
    {
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    }
    szDataIn[block_num * BLOCK_SIZE] = '\0';

    //���ܺ������
    char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

    //���н���AES��CBCģʽ����
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
string DecryptionAES(const string& strSrc) //AES����
{
    string strData = base64_decode(strSrc);
    size_t length = strData.length();
    //����
    char* szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //����
    char* szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);

    //����AES��CBCģʽ����
    AES aes;
    aes.MakeKey(g_key, g_iv, 32, 16);
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

    //ȥPKCS7Padding���
    if (0x00 < szDataOut[length - 1] && szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                cout << "ȥ���ʧ�ܣ����ܳ�����" << endl;
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
DWORD WINAPI ServerThread(LPVOID IpParameter) //�������˴����߳�
{
    //�½�һ��socket����ͨ��
    SOCKET newsocket = *(SOCKET*)IpParameter;//LPVOIDΪ��ָ�����ͣ���Ҫ��ת��SOCKET���������ã�����ʹ�ô����SOCKET
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
                cout << "���ܺ�:" << str3 << endl;
            }
            else if (r.type == aes)
            {
                cout << "�յ����ܺ��aes��ԿΪ��" << r.msg;
                BigInt xx = BigInt(r.msg);
                BigInt p = GeneratePrime();
                BigInt q = GeneratePrime();
                BigInt n = p * q;
                BigInt t = (p - 1) * (q - 1);
                BigInt e, d, y, temp;
                while (1)
                {
                    //������t���ʵ�e
                    e.Random();
                    while (!(Gcd(e, t) == 1))
                    {
                        e.Random();
                    }
                    //����չŷ������㷨��ͼ���eģt�ĳ˷���Ԫ
                    temp = ExtendedGcd(e, t, d, y);
                    //e*dģt���Ϊ1��˵��dȷʵ��eģt�ĳ˷���Ԫ
                    temp = (e * d) % t;
                    if (temp == 1)
                        break;
                    //������������e
                }
                BigInt ae;
                ae.Random();
                BigInt m2 = PowerMode(xx, d, n);
                cout << "���ܺ������Ϊ��" << endl;
                ae.display();
                cout << "���ڿ��Կ�ʼͨ��..." << endl;
            }
        }
        memset(recvBuf, 0, sizeof(recvBuf));
    }
    return 0;
}

int main() {
    //��ʼ��socket��
    WSADATA wsa;//��ʼ�����绷��
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
    //ʹ��2.2�汾��socket������ֵ������0��˵����ʼ��ʧ��,WSAStartup�������ڳ����г�ʼ��������Windows����
    {
        cout << "----Server: WSAStartup Error----" << endl;
        return 0;
    }
    else {
        cout << "----Server: WSAStartup Success----" << endl;
    }
    //����socket
    SOCKET listensocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//AF_INETʹ��IPV4��ַ��SOCK_STREAMʹ�������䣬IPPROTO_TCPʹ��TCPЭ��
    if (listensocket == INVALID_SOCKET) {
        cout << "----Server: Socket Error----" << endl;
        return 0;//�׽��ִ���ʧ��
    }
    else {
        cout << "----Server: Socket Success----" << endl;
    }
    // һ���󶨵�ַ:��IP��ַ,�ж˿ں�,��Э��� ����������ַ�����һ���ṹ������
    sockaddr_in listenaddr;//sockaddr_in��internet�������׽��ֵĵ�ַ��ʽ
    memset(&listenaddr, 0, sizeof(sockaddr_in));//��ʼ���ṹ��
    listenaddr.sin_family = AF_INET;//�ͷ�������socketһ����sin_family��ʾЭ��أ�ʹ��IPv4�ĵ�ַ
    listenaddr.sin_port = htons(PORT);//�˿ں�����Ϊ8000
    listenaddr.sin_addr.S_un.S_addr = inet_addr(IP);//����˵�ַ����Ϊ����ip��ַ
    //�󶨷�������socket�ʹ���õĵ�ַ
    if (bind(listensocket, (SOCKADDR*)&listenaddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "----Server: Bind Error----" << endl;
        return 0;
    }
    else {
        cout << "----Server: Bind Success to:" << PORT <<"----"<<endl;
        flag = 1;
    }
    // ��������
    listen(listensocket, 10);//�������г���Ϊ10
    cout << "----Server: Start Listening...----" << endl;
    sockaddr_in clientaddr;
    int len = sizeof(sockaddr_in);
    
    // ������������ʱ�����տͻ��˵���������
    while (flag) {
        // ���տͻ��˵��������󲢴����µ��׽���
        SOCKET newsocket = accept(listensocket, (SOCKADDR*)&clientaddr, &len);
        if (newsocket != INVALID_SOCKET) {
            cout << "----Server:Connection Accepted----" << endl;
            cout << "=============Enter exit to Close Connection=============" << endl;
            //RSA����
            //����������
            BigInt p = GeneratePrime();
            //16������ʽ��ʾ
            BigInt q = GeneratePrime();
            BigInt n = p * q;
            BigInt t = (p - 1) * (q - 1);
            //eΪ����Կ,dΪ����Կ����eģt�ĳ˷���Ԫ,y���ڲ�����չŷ��������㣬�洢tģe�ĳ˷���Ԫ
            BigInt e, d, y, temp;
            while (1)
            {
                //������t���ʵ�e
                e.Random();
                while (!(Gcd(e, t) == 1))
                {
                    e.Random();
                }
                //����չŷ������㷨��ͼ���eģt�ĳ˷���Ԫ
                temp = ExtendedGcd(e, t, d, y);
                //e*dģt���Ϊ1��˵��dȷʵ��eģt�ĳ˷���Ԫ
                temp = (e * d) % t;
                if (temp == 1)
                    break;
                //������������e
            }
            cout << "server�˹�Կ��Կ������" << endl;
            BigInt ae;
            ae.Random();//���� ��Ϊaes��Կ
            BigInt c = PowerMode(ae, e, n);
            string c_ = c.tohex();
            char recvBuf[MaxBufSize];
            char sendBuf[MaxBufSize];
            memset(recvBuf, 0, sizeof(recvBuf));
            memset(sendBuf, 0, sizeof(sendBuf));
            message m;
            //�����������ӵ��̣߳�����Ҫ�������ֱ�ӹر�
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
                        cout << "���ܺ�:" << str2 << endl;
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
    WSACleanup();//�������绷�����ͷ�socket��ռ����Դ
    cout << "----Server:WSA Cleaned Up----" << endl;
    system("pause");
    return 0;
}

