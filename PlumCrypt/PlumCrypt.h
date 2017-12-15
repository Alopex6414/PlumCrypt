/*
*     COPYRIGHT NOTICE
*     Copyright(c) 2017, Team Shanghai Dream Equinox
*     All rights reserved.
*
* @file		PlumCrypt.h
* @brief	This Program is PlumCrypt DLL Project.
* @author	Alopex/Helium
* @version	v1.00a
* @date		2017-12-13	v1.00a	alopex	Create Project
*/
#pragma once

#ifndef __PLUMCRYPT_H_
#define __PLUMCRYPT_H_

//Include Windows Header File
#include <Windows.h>

//Include C/C++ Run Header File
#include <stdio.h>

//Include Crypt Header File
#include "PlumCipherA.h"

//Macro Definition
#ifdef	PLUMCRYPT_EXPORTS
#define PLUMCRYPT_API	__declspec(dllexport)
#else
#define PLUMCRYPT_API	__declspec(dllimport)
#endif

#define CRYPTARRAYSIZE	1024

//Struct Definition
typedef struct
{
	char cFileName[24];
	char cCodeAuthor[8];
	DWORD dwFileSize;
	DWORD dwLuckyNum[4];
} PlumFileInfo;

//Class Definition
class PLUMCRYPT_API CPlumCrypt
{
private:


public:
	CPlumCrypt();
	virtual ~CPlumCrypt();

	//AES Crypt
	virtual void PlumEnCryptFileA(const char* pSrc, char* pDest, DWORD* pLuckyArr);
	virtual void PlumDeCryptFileA(const char* pSrc, char* pDest, DWORD* pLuckyArr);
	virtual void PlumEnCryptFileExA(const char* pSrc, char* pDest, DWORD* pLuckyArr);
	virtual void PlumDeCryptFileExA(const char* pSrc, char* pDest);
};

#endif