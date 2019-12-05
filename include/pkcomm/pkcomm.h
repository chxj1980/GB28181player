/**************************************************************
 *  Filename:    pkcomm.h
 *  Copyright:   Shanghai Peakinfo Co., Ltd.
 *
**************************************************************/
#ifndef _PK_COMM_H_
#define _PK_COMM_H_

#ifdef _WIN32
#	ifdef pkcomm_EXPORTS
#		define PKCOMM_API __declspec(dllexport)
#	else
#		define PKCOMM_API __declspec(dllimport)
#	endif
#else//_WIN32
#	define PKCOMM_API __attribute__ ((visibility ("default")))
#include "sys/types.h"
#endif//_WIN32

#include <time.h>
#include <string>
#include <list>
#include <vector>
using namespace std;

#ifndef PK_SUCCESS
#define PK_SUCCESS								0
#endif 

#define PK_LONGFILENAME_MAXLEN					1024			// 文件全路径的最大长度(实际长度受限于操作系统，windows下文件夹长度小于249，文件名全路径长度小于260)
#define PK_SHORTFILENAME_MAXLEN					260				// 文件全名称(不含路径)的最大长度
#define PK_HOSTNAMESTRING_MAXLEN				64				// 主机名称的最大程度

#ifdef _WIN32
#define PK_OS_DIR_SEPARATOR						"\\"
#else
#define PK_OS_DIR_SEPARATOR						"/"
#endif

class PKComm  
{
private:
	PKComm();
public:
	~PKComm();

	// 得到PEAK的安装目录
	PKCOMM_API static const char* GetHomePath();

	// 得到PEAK的配置文件所在目录
	PKCOMM_API static const char* GetConfigPath();

	// 得到bin目录的路径
	PKCOMM_API static const char* GetBinPath();

	// 获取进程名称，即可执行文件名称（不包含扩展名）
	PKCOMM_API static const char* GetProcessName();

	// 得到PEAK的日志文件所在目录
	PKCOMM_API static const char* GetLogPath();

	// 得到PEAK的运行时文件存放目录
	PKCOMM_API static const char* GetRunTimeDataPath(); 

	// 得到ICV的运行时文件存放目录
	PKCOMM_API static void Sleep(unsigned nMilSeconds);
};


class PKFileHelper  
{
public:
	//////////////////////////////////////////////////////////////////////////
	// File Dir operation
	PKCOMM_API static int WriteToFile(const char *szAbsPathName, const char *pFileContent, int lFileLen);

	// Directory operation
	// Concat directory
	PKCOMM_API static int ConCatDir(const char * szDirName, const char * szAbsParentDir, char *szResultDir, int lResultDirBufLen);

	// Concat directory
	PKCOMM_API static int ConCatDirAndFile(const char * szFileName, const char * szAbsParentDir, char *szResultPathName, int lResultDirBufLen);

	// create directory recursively
	PKCOMM_API static int CreateDir(const char * szDirName, const char * szAbsParentDir);

	// create directory recursively
	PKCOMM_API static int CreateDir(const char * szAbsDirPath);

	// Delete directory recursively
	PKCOMM_API static int DeleteDir(const char * szDirName, const char * szAbsParentDir);

	// is given pathname a directory 
	PKCOMM_API static bool IsDirectory(const char *szAbsDir);

	// is given pathname a directory 
	PKCOMM_API static bool IsDirectoryExist(const char *szAbsDir);

	// Delete directory recursively
	PKCOMM_API static int DeleteDir(const char * szAbsParentDir);

	// Rename directory
	PKCOMM_API static int RenameDir(const char * szOldDirName, const char * szNewDirName, const char * szAbsParentDir);

	// list sub directory
	PKCOMM_API static int ListSubDir(const char * szAbsParentDir, std::list<std::string> &dirNameList);

	// list files in directory
	PKCOMM_API static int ListFilesInDir(const char * szAbsParentDir, std::list<std::string> &fileNameList);

	// Delete a file
	PKCOMM_API static int DeleteAFile(const char * szFileName, const char * szAbsParentDir);
	
	PKCOMM_API static int CopyFiles(const char *pSrcDir, const char *pDstDir);

	PKCOMM_API static int ReadFile(const char *pFileName, char **pFileContent, int *lFileSize);  // 需要自己释放pFileContent的内存

	// file is exist
	PKCOMM_API static bool IsFileExist(const char * szFileName, const char * szAbsParentDir);

	// file is exis::
	PKCOMM_API static bool IsFileExist(const char * szFullPathName);

	// Regulate file path
	PKCOMM_API static int RegulatePathName(char * szPathName, int lPathNameLen);

	// 将相对路径转换为绝对路径（以工作路径作为基准目录）
	PKCOMM_API static int RelativeToFullPathName(const char *pszRelativePathName, char *pszFullPathName, int lFullPathSize);

	// 将相对路径转换为绝对路径（以指定路径作为基准目录）
	PKCOMM_API static int RelativeToFullPathNameEx(const char *pszRelativePathName, const char *pszParentPath, char *pszFullPathName, int lFullPathSize);

	// 获取工作路径，一般为执行文件的路径,如"c:\\d\e\\".如果未预先设置，则调用getcwd取当前工作路径
	PKCOMM_API static int GetWorkingDirectory(char *szWorkDirBuff, int lWorkDirBuffLen);

	// 获取工作路径，一般为执行文件的路径,如"c:\\d\e\\"
	PKCOMM_API static int SetWorkingDirectory(const char *szWorkDirBuff);

	// 将文件路径名称分为路径及名称，如C:\\abc\\def\\test.dat---> C:\\abc\\def\\ 和 test.dat
	PKCOMM_API static int SeparatePathName(const char *szPathName, char *szPath, int lPathLen, char *szName, int NameLen);

};

class PKStringHelper  
{
public:
	PKCOMM_API static int		Safe_StrNCpy(char * szDest, const char * szSource, int nDestBuffLen);
	PKCOMM_API static int		StringToInt(const char * szValue);
	PKCOMM_API static int		StringToIntEx(const char * szValue, int nDefault);
	PKCOMM_API static double	StringToDouble(const char * szValue);
	PKCOMM_API static int		StriCmp(const char * szCmp1, const char *szCmp2);
	PKCOMM_API static int		StrEscape(const char * szSrc, char *szEscape, size_t nEscapeBuffLen, char cEscaped, char cEscaping);
	PKCOMM_API static vector<string>  StriSplit(string str,string pattern);
	PKCOMM_API static char *	Strtok(char *s, const char *tokens, char **lasts); // 安全的split函数
	PKCOMM_API static void		Replace(std::string & sBig, const std::string & sSrc, const std::string &sDst);
	PKCOMM_API static int		HexDumpBuf(const char *szBuffer, unsigned int nCharBuffLen, char *szHexBuf, unsigned int nHexBufLen, unsigned int *pnRetHexBufLen);
	PKCOMM_API static int		HexStr2Buffer(const char *szHexStr, char *szBuffer, unsigned int *pnBufLen);
	PKCOMM_API static int		Snprintf(char *szOutBuf, int nOutBufLen, const char *szFormat,...) /* ?孛?*/;
};

class PKTimeHelper  
{
public:
	PKCOMM_API static unsigned int String2Time(char * date_and_time); // yyyy-hh-dd HH:mm:ss	static char * Time2String(char * date_and_time,  int date_and_timelen, unsigned int nTimeSeconds); // 高精度时间转换为时间字符串
	PKCOMM_API static char * Time2String(char * date_and_time,  int date_and_timelen, unsigned int nSeconds); // yyyy-hh-dd HH:mm:ss	static char * Time2String(char * date_and_time,  int date_and_timelen, unsigned int nTimeSeconds); // 高精度时间转换为时间字符串
	PKCOMM_API static char * GetCurTimeString(char * date_and_time,  int date_and_timelen); // 高精度时间转换为时间字符串
	PKCOMM_API static char * HighResTime2String(char * date_and_time,  int date_and_timelen, unsigned int nSeconds, unsigned int nMillSeconds); // 高精度时间转换为时间字符串
	PKCOMM_API static char * GetCurHighResTimeString(char * date_and_time,  int date_and_timelen); // 高精度时间转换为时间字符串
	PKCOMM_API static unsigned int GetHighResTime(unsigned int *pnMilSeconds); // 返回秒
	PKCOMM_API static unsigned int String2HighResTime(const char *szYYmmddHHMMSSddd, unsigned int *pnMilSeconds);
	PKCOMM_API static void	Sleep(unsigned int nMilSeconds);
};

class PKCodingConv  
{
public:
	PKCOMM_API static int AnsiToUtf8(char * buf, int buf_len, const char * src, int src_len = 0);	// Ansi/GBK--->UTF8
	PKCOMM_API static string AnsiToUtf8(string &strVal);			// Ansi/GBK--->UTF8
	PKCOMM_API static char * AnsiToUtf8(char * src, int src_len);	// Ansi/GBK--->UTF8

	PKCOMM_API static int Utf8ToAnsi(char * buf, int buf_len, const char * src, int src_len = 0);	// UTF8--->Ansi/GBK
	PKCOMM_API static char * Utf8ToAnsi(char * src, int src_len);	// UTF8--->Ansi/GBK
	PKCOMM_API static string Utf8ToAnsi(string &strVal);			// UTF8--->Ansi/GBK

	PKCOMM_API static void AnsiToUnicode(const string &strInput, wstring &strOutput);	// Ansi/GBK---->Unicode
	PKCOMM_API static void UnicodeToAnsi(const wstring &strInput, string &strOutput);	// Unicode--->Ansi/GBK
};

#endif // _PK_COMM_H_
