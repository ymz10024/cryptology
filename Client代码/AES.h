#pragma once

#ifndef _AES_H
#define _AES_H
#include <exception>
#include <cstring>
#include <string>
#define BLOCK_SIZE 16
using namespace std;

class AES
{
public:
	enum
	{
		ECB = 0, CBC = 1, CFB = 2
	};

private:
	enum
	{
		DEFAULT_BLOCK_SIZE = 16
	};
	enum
	{
		MAX_BLOCK_SIZE = 32, MAX_ROUNDS = 14, MAX_KC = 8, MAX_BC = 8
	};
public:
	AES();
	virtual ~AES();
private:
	bool m_bKeyInit;
	int m_Ke[MAX_ROUNDS + 1][MAX_BC];
	int m_Kd[MAX_ROUNDS + 1][MAX_BC];
	int m_keylength;
	int m_blockSize;
	int m_iROUNDS;
	char m_chain0[MAX_BLOCK_SIZE];
	char m_chain[MAX_BLOCK_SIZE];
	int tk[MAX_KC];
	int a[MAX_BC];
	int t[MAX_BC];
private:
	void Xor(char* buff, char const* chain);
	void DefEncryptBlock(char const* in, char* result);
	void DefDecryptBlock(char const* in, char* result);
	void EncryptBlock(char const* in, char* result);
	void DecryptBlock(char const* in, char* result);
public:
	void MakeKey(char const* key, char const* chain, int keylength =
		DEFAULT_BLOCK_SIZE, int blockSize = DEFAULT_BLOCK_SIZE);
	void Encrypt(char const* in, char* result, size_t n, int iMode = ECB);
	void Decrypt(char const* in, char* result, size_t n, int iMode = ECB);
};

#endif 
