


#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <assert.h>
#include <intrin.h>
#define LINE(s) TEXT(s "\n")

#define DO_ENCODE   1
#define DO_DECODE   2
#define DO_SHOWINFO 3

typedef struct
{
	LPTSTR pszSource;
	HANDLE hSourceFile;
	HANDLE hSourceMap;
	LPVOID pvSource;
	DWORD  cbSource;

	LPTSTR pszInput;
	HANDLE hInputFile;
	HANDLE hInputMap;
	LPVOID pvInput;
	DWORD  cbInput;

	LPTSTR pszOutput;
	HANDLE hOutputFile;
	HANDLE hOutputMap;
	LPVOID pvOutput;

	DWORD  dwOffset;
	BOOL   bXor;
	WORD   wXor;
} LSB, *PLSB;

VOID LsbCloseMap(HANDLE hFile, HANDLE hMap, LPVOID pView);
VOID LsbDecode(PLSB pLsb);
VOID LsbEncode(PLSB pLsb);
BOOL LsbMapFile(LPTSTR pszFileName, BOOL bForWriting, HANDLE * phFile, HANDLE * phMap, LPVOID * ppvMap, LPDWORD lpdwSize);
BYTE LsbReadBits(PLSB pLsb, int nBits);
VOID LsbSourceInfo(PLSB pLsb);
VOID LsbWriteBits(PLSB pLsb, BYTE bValue, int nBits);
void Usage(void);

int __cdecl _tmain(int argc, TCHAR *argv[])
{

	LSB lsb;
	int argi;
	TCHAR * parg;
	DWORD dwAction;
	
	ZeroMemory(&lsb, sizeof(LSB));

	if(argc < 3)
	{
		_tprintf(LINE("Arguments are missing."));
		Usage();
		return -1;
	}
	
	dwAction = 0;
	for(argi = 1; argi < argc - 1; argi++)
	{
		parg = argv[argi];
		if(*parg != '-' && *parg != '/')
		{
			_tprintf(LINE("Invalid argument: %s"), argv[argi]);
			Usage();
			return -1;
		}
		parg++;
		switch(*parg)
		{
			case 'e':
				dwAction = DO_ENCODE;
				lsb.pszSource = argv[++argi];
				break;
			case 'd':
				dwAction = DO_DECODE;
				lsb.pszSource = argv[++argi];
				break;
			case 'w':
				lsb.pszInput = argv[++argi];
				break;
			case 'i':
				lsb.pszOutput = argv[++argi];
				break;
			case 'x':
				lsb.bXor = TRUE;
				lsb.wXor = (BYTE)(atoi(argv[++argi]) & 0xFF);
				lsb.wXor |= (lsb.wXor << 8);
				break;
			case 's':
				dwAction = DO_SHOWINFO;
				lsb.pszSource = argv[++argi];
				break;
			case 'h':
				Usage();
				return 0;
			default:
				_tprintf(LINE("Unknown argument: %s"), argv[argi]);
				Usage();
				return -1;
		}
	}

	if(lsb.pszSource == NULL)
	{
		_tprintf(LINE("Bitmap source not specified."));
		Usage();
		return -1;
	}

	if(!LsbMapFile(lsb.pszSource, FALSE, &lsb.hSourceFile, &lsb.hSourceMap, &lsb.pvSource, &lsb.cbSource))
	{
		return -1;
	}

	switch(dwAction)
	{
		case DO_DECODE:
			LsbDecode(&lsb);
			break;
		case DO_ENCODE:
			LsbEncode(&lsb);
			break;
		case DO_SHOWINFO:
			LsbSourceInfo(&lsb);
			break;
	}

	LsbCloseMap(lsb.hSourceFile, lsb.hSourceMap, lsb.pvSource);

	return 0;
}	

VOID LsbCloseMap(HANDLE hFile, HANDLE hMap, LPVOID pView)
{
	if(pView != NULL) UnmapViewOfFile(pView); 
	if(hMap != NULL) CloseHandle(hMap);
	if(hFile != NULL) CloseHandle(hFile);
}

VOID LsbDecode(PLSB pLsb)
{
	PBITMAPFILEHEADER pFile;
	PBITMAPINFOHEADER pInfo;
	DWORD cbRow, cbActual, nRow, nCol;
	BYTE * pSource;
	BYTE bValue;
	DWORD dwSize, dwIndex;

	pFile = pLsb->pvSource;
	pInfo = (PBITMAPINFOHEADER)(((ULONG_PTR)pLsb->pvSource) + sizeof(BITMAPFILEHEADER));

	// Calculate the row size
	cbRow = pInfo->biWidth * 3;
	cbActual = (DWORD)(cbRow + 3) & (~(DWORD)3);
	// Validate target size
	dwSize = ((cbActual - cbRow) * pInfo->biHeight) + ((pInfo->biWidth * pInfo->biHeight * 3) >> 3);
	if(!LsbMapFile(pLsb->pszOutput, TRUE, &pLsb->hOutputFile, &pLsb->hOutputMap, &pLsb->pvOutput, &dwSize))
	{
		return;
	}

	// Validate header
	if(pFile->bfType != 0x4D42 
	|| pInfo->biSize != 0x28 
	|| pInfo->biBitCount != 24 
	|| pInfo->biCompression != BI_RGB
	){
		_tprintf(TEXT("Invalid type of bitmap (or file)...\n"));
		return;
	}

	// Calculate the row size
	cbRow = pInfo->biWidth * 3;
	cbActual = (DWORD)(cbRow + 3) & (~(DWORD)3);
	
	pSource = ((PBYTE)pLsb->pvSource) + pFile->bfOffBits;
	for(nRow = 0; nRow < (DWORD)pInfo->biHeight; nRow++)
	{
		for(nCol = 0; nCol < cbRow; nCol += 3)
		{
			bValue = 
			      (((*(pSource + nCol + 0)) & 1) << 2)
			    | (((*(pSource + nCol + 1)) & 1) << 1)
			    |  ((*(pSource + nCol + 2)) & 1);
			LsbWriteBits(pLsb, bValue, 3);
		}
		for(nCol = cbRow; nCol < cbActual; nCol++)
		{
			LsbWriteBits(pLsb, *(pSource + nCol), 8);
		}
		pSource += cbActual;
	}
	// Xor Decode 
	if(pLsb->bXor) 
	{
		for(dwIndex = 0; dwIndex < dwSize; dwIndex++)
		{
			*((PBYTE)pLsb->pvOutput + dwIndex) ^= pLsb->wXor;
		}
	}
	LsbCloseMap(pLsb->hOutputFile, pLsb->hOutputMap, pLsb->pvOutput);
}

VOID LsbEncode(PLSB pLsb)
{
	PBITMAPFILEHEADER pFile;
	PBITMAPINFOHEADER pInfo;
	PBYTE pSource, pOutput;
	DWORD dwOffset, cbRow, cbActual;
	DWORD nRow, nCol;
	BYTE bBits;

	if(pLsb->pszInput == NULL || pLsb->pszOutput == NULL)
	{
		_tprintf(TEXT("Arguments are missing...\n"));
		return;
	}
	
	// Validate header
	pFile = pLsb->pvSource;
	pInfo = (PBITMAPINFOHEADER)(((ULONG_PTR)pLsb->pvSource) + sizeof(BITMAPFILEHEADER));
	
	if(pFile->bfType != 0x4D42 
	|| pInfo->biSize != 0x28 
	|| pInfo->biBitCount != 24 
	|| pInfo->biCompression != BI_RGB
	){
		_tprintf(TEXT("Invalid type of bitmap (or file)...\n"));
		return;
	}
	if(!LsbMapFile(pLsb->pszInput, FALSE, &pLsb->hInputFile, &pLsb->hInputMap, &pLsb->pvInput, &pLsb->cbInput))
	{
		return;
	}

	// Calculate the row size
	cbRow = pInfo->biWidth * 3;
	cbActual = (DWORD)(cbRow + 3) & (~(DWORD)3);
	// Validate target size
	if(pLsb->cbInput > ((cbActual - cbRow) * pInfo->biHeight) + ((pInfo->biWidth * pInfo->biHeight * 3) >> 3))
	{
		_tprintf(TEXT("Not enough space in bitmap...\n"));
		LsbCloseMap(pLsb->hInputFile, pLsb->hInputMap, pLsb->pvInput);
		return;
	}

	if(!LsbMapFile(pLsb->pszOutput, TRUE, &pLsb->hOutputFile, &pLsb->hOutputMap, &pLsb->pvOutput, &pLsb->cbSource))
	{
		LsbCloseMap(pLsb->hInputFile, pLsb->hInputMap, pLsb->pvInput);
		return;
	}

	// Copy the headers
	pSource = pLsb->pvSource;
	pOutput = pLsb->pvOutput;
	for(dwOffset = 0; dwOffset < pFile->bfOffBits; dwOffset++)
	{
		*(pOutput + dwOffset) = *(pSource + dwOffset);
	}

	// Copy bytes and insert bits
	pSource = ((PBYTE)pLsb->pvSource) + pFile->bfOffBits;
	pOutput = ((PBYTE)pLsb->pvOutput) + pFile->bfOffBits;
	for(nRow = 0; nRow < (DWORD)pInfo->biHeight; nRow++)
	{
		for(nCol = 0; nCol < cbRow; nCol += 3)
		{
			bBits = LsbReadBits(pLsb, 3);
			//B
			if(bBits & 0x4)
				*(pOutput + nCol + 0) = (*(pSource + nCol + 0)) | 1;
			else
				*(pOutput + nCol + 0) = (*(pSource + nCol + 0)) & 0xFE;
			//G
			if(bBits & 0x2)
				*(pOutput + nCol + 1) = (*(pSource + nCol + 1)) | 1;
			else
				*(pOutput + nCol + 1) = (*(pSource + nCol + 1)) & 0xFE;
			//R
			if(bBits & 0x1)
				*(pOutput + nCol + 2) = (*(pSource + nCol + 2)) | 1;
			else
				*(pOutput + nCol + 2) = (*(pSource + nCol + 2)) & 0xFE;
		}
		for(nCol = cbRow; nCol < cbActual; nCol++)
		{
			*(pOutput + nCol) = LsbReadBits(pLsb, 8);
		}
		pSource += cbActual;
		pOutput += cbActual;
	}

	LsbCloseMap(pLsb->hOutputFile, pLsb->hOutputMap, pLsb->pvOutput);
	LsbCloseMap(pLsb->hInputFile, pLsb->hInputMap, pLsb->pvInput);
}

BOOL LsbMapFile(LPTSTR pszFileName, BOOL bForWriting, HANDLE * phFile, HANDLE * phMap, LPVOID * ppvMap, LPDWORD lpdwSize)
{
	DWORD dwFileAccess  = FALSE == bForWriting ? GENERIC_READ  : GENERIC_READ | GENERIC_WRITE;
	DWORD dwDisposition = FALSE == bForWriting ? OPEN_EXISTING : CREATE_ALWAYS;
	DWORD dwProtect     = FALSE == bForWriting ? PAGE_READONLY : PAGE_READWRITE;
	DWORD dwMapAccess   = FALSE == bForWriting ? FILE_MAP_READ : FILE_MAP_READ | FILE_MAP_WRITE;
	DWORD dwHigh;
	*phFile = CreateFile(pszFileName, dwFileAccess, 0, NULL, dwDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
	if(*phFile != INVALID_HANDLE_VALUE)
	{
		if(bForWriting == FALSE)
		{
			*lpdwSize = GetFileSize(*phFile, &dwHigh);
		}
		*phMap = CreateFileMapping(*phFile, NULL, dwProtect, 0, *lpdwSize, NULL);
		if(*phMap != NULL)
		{
			*ppvMap = MapViewOfFile(*phMap, dwMapAccess, 0, 0, *lpdwSize);
			if(*ppvMap != NULL)
			{
				return TRUE;
			}
			_tprintf(TEXT("MapViewOfFile error GetLastError: %d. \"%s\"\n"), GetLastError(), pszFileName);
			CloseHandle(*phMap);
		}
		else
		{
			_tprintf(TEXT("CreateFileMapping error GetLastError: %d. \"%s\"\n"), GetLastError(), pszFileName);
		}
		CloseHandle(*phFile);
	}
	else
	{
		_tprintf(TEXT("CreateFile error GetLastError: %d. \"%s\"\n"), GetLastError(), pszFileName);
	}
	*phMap = NULL;		
	*phFile = NULL;
	return FALSE;
}

BYTE LsbReadBits(PLSB pLsb, int nBits)
{
	DWORD dwOffset;
	WORD  wCurrent;
	BYTE bResult;

	dwOffset = pLsb->dwOffset >> 3;
	if(dwOffset < pLsb->cbInput)
	{
		wCurrent = (WORD)*((PBYTE)pLsb->pvInput + dwOffset) << 8;
		if(dwOffset + 1 < pLsb->cbInput)
		{
			wCurrent |= (WORD)*(((PBYTE)pLsb->pvInput) + dwOffset + 1) & 0x00FFui16;
		}
	}
	else
	{
		return 0;
	}

	if(pLsb->bXor)
	{
		wCurrent ^= pLsb->wXor;
	}
	dwOffset = pLsb->dwOffset & 0x00000007ui32;
	wCurrent <<= dwOffset;

	switch(nBits)
	{
		case 1:
			bResult = wCurrent >> 15;
			break;
		case 2:
			bResult = wCurrent >> 14;
			break;
		case 3:
			bResult = wCurrent >> 13;
			break;
		case 4:
			bResult = wCurrent >> 12;
			break;
		case 5:
			bResult = wCurrent >> 11;
			break;
		case 6:
			bResult = wCurrent >> 10;
			break;
		case 7:
			bResult = wCurrent >> 9;
			break;
		case 8:
			bResult = wCurrent >> 8;
			break;
		default:
			assert(0);
			return 0;
	}

	pLsb->dwOffset += nBits;

	return bResult;
}

VOID LsbSourceInfo(PLSB pLsb)
{
	PBITMAPFILEHEADER pFile;
	PBITMAPINFOHEADER pInfo;
	DWORD cbRow, cbActual, cbFreeRow, cbBits;

	_tprintf(TEXT("File: \"%s\"\n"), pLsb->pszSource);

	_tprintf(TEXT("Bitmap File Header\n"));
	pFile = pLsb->pvSource;
	_tprintf(TEXT("\tType: \"%c%c\" 0x%04X\n"), *(char*)pLsb->pvSource, *(((char*)pLsb->pvSource) + 1), pFile->bfType);
	if(pFile->bfType != 0x4D42)
	{
		_ftprintf(stderr, TEXT("Invalid signature...\n"));
		return;
	}
	_tprintf(TEXT("\tReserved1: 0x%04X\n"), pFile->bfReserved1);
	_tprintf(TEXT("\tReserved2: 0x%04X\n"), pFile->bfReserved2);
	_tprintf(TEXT("\tOffset bits: 0x%08X\n"), pFile->bfOffBits);

	_tprintf(TEXT("Bitmap Info Header\n"));
	pInfo = (PBITMAPINFOHEADER)(((ULONG_PTR)pLsb->pvSource) + ((ULONG_PTR)sizeof(BITMAPFILEHEADER)));
	_tprintf(TEXT("\tSize: %d\n"), pInfo->biSize);
	if(pInfo->biSize != 0x28)
	{
		_ftprintf(stderr, TEXT("Unexpected header... various headers exist, expected BITMAPINFOHEADER size 0x28(40).\n"));
		return;
	}
	_tprintf(TEXT("\tWidth: %d\n"), pInfo->biWidth);
	_tprintf(TEXT("\tHeight: %d\n"), pInfo->biHeight);
	_tprintf(TEXT("\tPlanes: %d\n"), pInfo->biPlanes);
	_tprintf(TEXT("\tBits per pixel: %d\n"), pInfo->biBitCount);
	_tprintf(TEXT("\tCompression: 0x%08X\n"), pInfo->biCompression);
	switch(pInfo->biCompression)
	{
		case BI_RGB:       _tprintf(TEXT("\t\tRGB: An uncompressed format.\n")); break;
		case BI_RLE8:      _tprintf(TEXT("\t\tRLE8: A run-length encoded (RLE) format for bitmaps with 8 bpp. The compression format is a 2-byte format consisting of a count byte followed by a byte containing a color index. For more information, see Bitmap Compression.\n")); break;
		case BI_RLE4:      _tprintf(TEXT("\t\tRLE4: An RLE format for bitmaps with 4 bpp. The compression format is a 2-byte format consisting of a count byte followed by two word-length color indexes. For more information, see Bitmap Compression.\n")); break;
		case BI_BITFIELDS: _tprintf(TEXT("\t\tBITFIELDS: Specifies that the bitmap is not compressed and that the color table consists of three DWORD color masks that specify the red, green, and blue components, respectively, of each pixel. This is valid when used with 16- and 32-bpp bitmaps.\n")); break;
		case BI_JPEG:      _tprintf(TEXT("\t\tJPEG: Indicates that the bitmap is a JPEG image.\n")); break;
		case BI_PNG:       _tprintf(TEXT("\t\tPNG: Indicates that the bitmap is a PNG image.\n")); break;
		default:           _tprintf(TEXT("\t\tUnknown compression...\n")); break;
	}
	_tprintf(TEXT("\tSize of bitmap: %d\n"), pInfo->biSizeImage);
	_tprintf(TEXT("\tPixels per meter X: %d\n"), pInfo->biXPelsPerMeter);
	_tprintf(TEXT("\tPixels per meter Y: %d\n"), pInfo->biYPelsPerMeter);
	_tprintf(TEXT("\tColors used: %d\n"), pInfo->biClrUsed);
	_tprintf(TEXT("\tImportant colors: %d\n"), pInfo->biClrImportant);

	_tprintf(TEXT("\nLSB Info\n"));
	if(pInfo->biCompression != BI_RGB || pInfo->biBitCount != 24)
	{
		_tprintf(LINE("\nlsb only supports RGB with 24 bits per pixel."));
		return;
	}
	cbRow = pInfo->biWidth * 3;
	cbActual = (DWORD)(cbRow + 3) & (~(DWORD)3);
	cbFreeRow = cbActual - cbRow;
	cbBits = pInfo->biHeight * pInfo->biWidth * 3;
	_tprintf(TEXT("\tActual bytes per row: %d\n"), cbActual);
	_tprintf(TEXT("\tUsed bytes per row: %d\n"), cbRow);
	_tprintf(TEXT("\tFree padding bytes per row: %d - %d = %d\n"), cbActual, cbRow, cbFreeRow);
	_tprintf(TEXT("\tFree padding bytes: %d * %d = %d\n"), cbFreeRow, pInfo->biHeight, cbFreeRow * pInfo->biHeight);
	_tprintf(TEXT("\tTotal LSB bits: %d * %d * 3 = %d\n"), pInfo->biWidth, pInfo->biHeight, cbBits);
	_tprintf(TEXT("\tTotal LSB bytes: %d / 8 = %d\n"), cbBits, cbBits >> 3);
	cbFreeRow *= pInfo->biHeight;
	cbBits >>= 3;
	_tprintf(TEXT("\tTotal extra bytes: %d + %d = %d\n"), cbFreeRow, cbBits, cbFreeRow + cbBits);
}

VOID LsbWriteBits(PLSB pLsb, BYTE bValue, int nBits)
{
	DWORD dwOffset, dwBitOffset;
	WORD wValue;
	dwOffset = pLsb->dwOffset >> 3;
	dwBitOffset = pLsb->dwOffset & 0x00000007ui32;
	wValue = (WORD)bValue << (16 - (dwBitOffset + nBits));
	*((PBYTE)pLsb->pvOutput + dwOffset) |= wValue >> 8;
	*((PBYTE)pLsb->pvOutput + dwOffset + 1) |= wValue & 0xFF;
	pLsb->dwOffset += nBits;

	//DWORD dwOffset, dwBitOffset;
	//WORD wValue;
	//BYTE b1, b2;

	//dwOffset = pLsb->dwOffset >> 3;
	//dwBitOffset = pLsb->dwOffset & 0x00000007ui32;

	//b1 = *((PBYTE)pLsb->pvOutput + dwOffset);
	//b2 = *((PBYTE)pLsb->pvOutput + dwOffset + 1);

	//wValue = (WORD)bValue << (16 - (dwBitOffset + nBits));
	//b1 |= wValue >> 8;
	//b2 |= wValue;

	//*((PBYTE)pLsb->pvOutput + dwOffset) = b1;
	//*((PBYTE)pLsb->pvOutput + dwOffset + 1) = b2;

	//pLsb->dwOffset += nBits;


}

void Usage(void)
{
	_tprintf(
		LINE("")
		LINE("Least Significant Bit")
		LINE("")
		LINE("lsb -encode bitmap -with input -into output [-xor 222]")
		LINE("lsb -decode bitmap -into output [-xor 222]")
		LINE("lsb -show image")
		LINE("lsb -help")
		LINE("")
		LINE(" -e -encode   Encode bitmap file.")
		LINE(" -d -decode   Decode bitmap file.")
		LINE(" -w -with     With input file as data.")
		LINE(" -i -into     Into output file.")
		LINE(" -x -xor      Use xor encoding.")
		LINE(" -s -show     Show image info.")
		LINE(" -h -help     Show this help")
		LINE("")
	);
}
