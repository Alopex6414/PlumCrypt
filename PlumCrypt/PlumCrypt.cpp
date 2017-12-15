/*
*     COPYRIGHT NOTICE
*     Copyright(c) 2017, Team Shanghai Dream Equinox
*     All rights reserved.
*
* @file		PlumCrypt.cpp
* @brief	This Program is PlumCrypt DLL Project.
* @author	Alopex/Helium
* @version	v1.00a
* @date		2017-12-13	v1.00a	alopex	Create Project
*/
#include "PlumCrypt.h"

//This Class is File EnCrypt/DeCrypt(文件加密/解密)

//------------------------------------------------------------------
// @Function:	 CPlumCrypt()
// @Purpose: CPlumCrypt构造函数
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
CPlumCrypt::CPlumCrypt()
{
}

//------------------------------------------------------------------
// @Function:	 ~CPlumCrypt()
// @Purpose: CPlumCrypt析构函数
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
CPlumCrypt::~CPlumCrypt()
{
}

//------------------------------------------------------------------
// @Function:	 PlumEnCryptFileA()
// @Purpose: PlumCryptFileA加密文件
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
void CPlumCrypt::PlumEnCryptFileA(const char* pSrc, char* pDest, DWORD* pLuckyArr)
{
	FILE* fin;
	FILE* fou;

	fopen_s(&fin, pSrc, "r+b");
	if (fin == NULL)
	{
		return;
	}

	fopen_s(&fou, pDest, "w+b");
	if (fou == NULL)
	{
		return;
	}

	CPlumCipherA* pCode = NULL;
	unsigned char KeyArr[16];

	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
		{
			KeyArr[4 * i + j] = (*(pLuckyArr + i) >> (8 * j)) & 0xff;
		}
	}

	pCode = new CPlumCipherA(KeyArr);

	unsigned char* pSrcArr = NULL;
	unsigned char* pDestArr = NULL;
	int nSrcSize = CRYPTARRAYSIZE;
	int nDestSize = CRYPTARRAYSIZE;
	int nReadSize = 0;
	int nWriteSize = 0;

	pSrcArr = (unsigned char*)malloc(nSrcSize*sizeof(unsigned char));
	pDestArr = (unsigned char*)malloc(nDestSize*sizeof(unsigned char));

	for (;;)
	{
		memset(pSrcArr, 0, nSrcSize);
		memset(pDestArr, 0, nDestSize);

		nReadSize = fread((void*)pSrcArr, sizeof(unsigned char), nSrcSize, fin);
		if (nReadSize == 0) break;
		if (nReadSize != nSrcSize)
		{
			while (nReadSize % 16)
			{
				++nReadSize;
			}
		}

		pCode->EnCrypt((void*)pSrcArr, (void*)pDestArr, nSrcSize);

		nWriteSize = fwrite((void*)pDestArr, sizeof(unsigned char), nReadSize, fou);
		if (nWriteSize == 0) break;
	}

	if (pSrcArr) free(pSrcArr);
	if (pDestArr) free(pDestArr);

	delete pCode;

	fclose(fou);
	fclose(fin);
}

//------------------------------------------------------------------
// @Function:	 PlumDeCryptFileA()
// @Purpose: PlumCryptFileA解密文件
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
void CPlumCrypt::PlumDeCryptFileA(const char* pSrc, char* pDest, DWORD* pLuckyArr)
{
	FILE* fin;
	FILE* fou;

	fopen_s(&fin, pSrc, "r+b");
	if (fin == NULL)
	{
		return;
	}

	fopen_s(&fou, pDest, "w+b");
	if (fou == NULL)
	{
		return;
	}

	CPlumCipherA* pCode = NULL;
	unsigned char KeyArr[16];

	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
		{
			KeyArr[4 * i + j] = (*(pLuckyArr + i) >> (8 * j)) & 0xff;
		}
	}

	pCode = new CPlumCipherA(KeyArr);

	unsigned char* pSrcArr = NULL;
	unsigned char* pDestArr = NULL;
	int nSrcSize = CRYPTARRAYSIZE;
	int nDestSize = CRYPTARRAYSIZE;
	int nReadSize = 0;
	int nWriteSize = 0;

	pSrcArr = (unsigned char*)malloc(nSrcSize*sizeof(unsigned char));
	pDestArr = (unsigned char*)malloc(nDestSize*sizeof(unsigned char));

	for (;;)
	{
		memset(pSrcArr, 0, nSrcSize);
		memset(pDestArr, 0, nDestSize);

		nReadSize = fread((void*)pSrcArr, sizeof(unsigned char), nSrcSize, fin);
		if (nReadSize == 0) break;

		pCode->DeCrypt((void*)pSrcArr, (void*)pDestArr, nSrcSize);

		nWriteSize = fwrite((void*)pDestArr, sizeof(unsigned char), nReadSize, fou);
		if (nWriteSize == 0) break;
	}

	if (pSrcArr) free(pSrcArr);
	if (pDestArr) free(pDestArr);

	delete pCode;

	fclose(fou);
	fclose(fin);
}

//------------------------------------------------------------------
// @Function:	 PlumEnCryptFileExA()
// @Purpose: PlumCryptFileA加密文件(Ex)(msg)
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
void CPlumCrypt::PlumEnCryptFileExA(const char* pSrc, char* pDest, DWORD* pLuckyArr)
{
	HANDLE hFileSrc;
	HANDLE hFileDest;
	HANDLE hFileMsg;

	//打开源文件
	hFileSrc = CreateFileA(pSrc, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileSrc == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileSrc);
		return;
	}

	//打开目标文件
	hFileDest = CreateFileA(pDest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileDest == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileDest);
		return;
	}

	//分析文件
	char* pTemp;
	char* pMsg;
	char* pSrcName;
	int nCount;

	pTemp = pDest;
	nCount = strlen(pTemp);
	pMsg = (char*)malloc((nCount + 1)*sizeof(char));
	strcpy_s(pMsg, (nCount + 1), pTemp);
	pTemp = strrchr(pMsg, '.');
	*pTemp = '.';
	*(pTemp + 1) = 'm';
	*(pTemp + 2) = 's';
	*(pTemp + 3) = 'g';
	*(pTemp + 4) = '\0';

	pTemp = strrchr((char*)pSrc, '\\');
	nCount = strlen(++pTemp);
	pSrcName = (char*)malloc((nCount + 1)*sizeof(char));
	strcpy_s(pSrcName, (nCount + 1), pTemp);

	//打开文件信息
	hFileMsg = CreateFileA(pMsg, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileMsg == INVALID_HANDLE_VALUE)
	{
		if (pMsg) free(pMsg);
		if (pSrcName) free(pSrcName);
		CloseHandle(hFileMsg);
		return;
	}

	CPlumCipherA* pCode = NULL;
	unsigned char KeyArr[16];

	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
		{
			KeyArr[4 * i + j] = (*(pLuckyArr + i) >> (8 * j)) & 0xff;
		}
	}

	pCode = new CPlumCipherA(KeyArr);

	unsigned char* pSrcArr = NULL;
	unsigned char* pDestArr = NULL;
	int nSrcSize = CRYPTARRAYSIZE;
	int nDestSize = CRYPTARRAYSIZE;
	int nReadSize = 0;
	int nWriteSize = 0;
	DWORD dwRealRead = 0;
	DWORD dwRealWrite = 0;
	DWORD dwFileSize = 0;

	dwFileSize = GetFileSize(hFileSrc, NULL);//获取文件长度

	pSrcArr = (unsigned char*)malloc(nSrcSize*sizeof(unsigned char));
	pDestArr = (unsigned char*)malloc(nDestSize*sizeof(unsigned char));

	for (;;)
	{
		memset(pSrcArr, 0, nSrcSize);
		memset(pDestArr, 0, nDestSize);

		ReadFile(hFileSrc, pSrcArr, nSrcSize, &dwRealRead, NULL);
		if (dwRealRead == 0) break;
		if (dwRealRead != nSrcSize)
		{
			while (dwRealRead % 16)
			{
				++dwRealRead;
			}
		}

		pCode->EnCrypt((void*)pSrcArr, (void*)pDestArr, nSrcSize);

		WriteFile(hFileDest, pDestArr, dwRealRead, &dwRealWrite, NULL);
		if (dwRealWrite == 0) break;
	}

	//写入Msg
	int i = 0;
	PlumFileInfo sMsg;
	DWORD dwMsgWrite;

	memset(&sMsg, 0, sizeof(sMsg));
	for (i = 0, pTemp = pSrcName; i < sizeof(sMsg.cFileName) && *pTemp != '\0'; ++i, ++pTemp)
	{
		*(sMsg.cFileName + i) = *pTemp;
	}
	memcpy((void*)(sMsg.cCodeAuthor), "alopex", sizeof("alopex"));
	memcpy((void*)(sMsg.dwLuckyNum), pLuckyArr, sizeof(sMsg.dwLuckyNum));
	sMsg.dwFileSize = dwFileSize;

	WriteFile(hFileMsg, &sMsg, sizeof(sMsg), &dwMsgWrite, NULL);

	if (pMsg) free(pMsg);
	if (pSrcName) free(pSrcName);
	if (pSrcArr) free(pSrcArr);
	if (pDestArr) free(pDestArr);

	delete pCode;

	CloseHandle(hFileMsg);
	CloseHandle(hFileDest);
	CloseHandle(hFileSrc);
}

//------------------------------------------------------------------
// @Function:	 PlumDeCryptFileExA()
// @Purpose: PlumCryptFileA解密文件(Ex)(msg)
// @Since: v1.00a
// @Para: None
// @Return: None
//------------------------------------------------------------------
void CPlumCrypt::PlumDeCryptFileExA(const char* pSrc, char* pDest)
{
	HANDLE hFileSrc;
	HANDLE hFileDest;
	HANDLE hFileMsg;

	//打开源文件
	hFileSrc = CreateFileA(pSrc, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileSrc == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileSrc);
		return;
	}

	//打开目标文件
	hFileDest = CreateFileA(pDest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileDest == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileDest);
		return;
	}

	//分析文件
	char* pTemp;
	char* pMsg;
	int nCount;

	pTemp = (char*)pSrc;
	nCount = strlen(pTemp);
	pMsg = (char*)malloc((nCount + 1)*sizeof(char));
	strcpy_s(pMsg, (nCount + 1), pTemp);
	pTemp = strrchr(pMsg, '.');
	*pTemp = '.';
	*(pTemp + 1) = 'm';
	*(pTemp + 2) = 's';
	*(pTemp + 3) = 'g';
	*(pTemp + 4) = '\0';

	//打开文件信息
	hFileMsg = CreateFileA(pMsg, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileMsg == INVALID_HANDLE_VALUE)
	{
		if (pMsg) free(pMsg);
		CloseHandle(hFileMsg);
		return;
	}

	//读入Msg
	PlumFileInfo sMsg;
	DWORD dwMsgRead;

	ReadFile(hFileMsg, &sMsg, sizeof(sMsg), &dwMsgRead, NULL);

	CPlumCipherA* pCode = new CPlumCipherA((unsigned char*)(sMsg.dwLuckyNum));
	unsigned char* pSrcArr = NULL;
	unsigned char* pDestArr = NULL;
	int nSrcSize = CRYPTARRAYSIZE;
	int nDestSize = CRYPTARRAYSIZE;
	int nReadSize = 0;
	int nWriteSize = 0;
	DWORD dwRealRead = 0;
	DWORD dwRealWrite = 0;
	DWORD dwWriteAllCount = 0;
	DWORD dwWriteLastSize = 0;
	DWORD dwWriteCount = 0;

	dwWriteAllCount = sMsg.dwFileSize / nSrcSize + 1;
	dwWriteLastSize = sMsg.dwFileSize % nSrcSize;

	pSrcArr = (unsigned char*)malloc(nSrcSize*sizeof(unsigned char));
	pDestArr = (unsigned char*)malloc(nDestSize*sizeof(unsigned char));

	for (;;)
	{
		memset(pSrcArr, 0, nSrcSize);
		memset(pDestArr, 0, nDestSize);

		ReadFile(hFileSrc, pSrcArr, nSrcSize, &dwRealRead, NULL);
		if (dwRealRead == 0) break;

		pCode->DeCrypt((void*)pSrcArr, (void*)pDestArr, nSrcSize);

		++dwWriteCount;
		if (dwWriteCount == dwWriteAllCount)
		{
			dwRealRead = dwWriteLastSize;
		}

		WriteFile(hFileDest, pDestArr, dwRealRead, &dwRealWrite, NULL);
		if (dwRealWrite == 0) break;
	}

	if (pMsg) free(pMsg);
	if (pSrcArr) free(pSrcArr);
	if (pDestArr) free(pDestArr);

	delete pCode;

	CloseHandle(hFileMsg);
	CloseHandle(hFileDest);
	CloseHandle(hFileSrc);
}