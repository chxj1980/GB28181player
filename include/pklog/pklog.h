/**************************************************************
 *  Filename:    pklog.h
 *
 *  Description: create.
 *
 *  @author:     shijunpu
**************************************************************/
#ifndef _PKLOG_H_
#define _PKLOG_H_

#ifdef _WIN32
#	ifdef pklog_EXPORTS
#		define PKLog_API __declspec(dllexport)
#	else
#		define PKLog_API __declspec(dllimport)
#	endif
#else
#	define PKLog_API __attribute__ ((visibility ("default")))
#endif//_WIN32

#include "pkcomm/pkcomm.h"

#ifndef PK_LOGLEVEL_DEBUG
#define PK_LOGLEVEL_DEBUG					0x01	// 调试信息
#define PK_LOGLEVEL_INFO					0x02	// 信息
#define PK_LOGLEVEL_WARN					0x04	// 警告
#define PK_LOGLEVEL_ERROR					0x08	// 错误信息
#define PK_LOGLEVEL_CRITICAL				0x10	// 关键错误
#define PK_LOGLEVEL_NOTICE					0x20	// 必须打印的注意事项
#define PK_LOGLEVEL_COMM					0x100	// 数据通讯。该级别和上述级别同列，并不是包含关系
#endif // PK_LOGLEVEL_DEBUG

#define LH_LOG(X) PKLog.LogMessage X

#define LH_DEBUG(X) LH_LOG((PK_LOGLEVEL_DEBUG,X))
#define LH_ERROR(X) LH_LOG((PK_LOGLEVEL_ERROR,X))
#define LH_INFO(X)  LH_LOG((PK_LOGLEVEL_INFO,X))
#define LH_WARN(X)  LH_LOG((PK_LOGLEVEL_WARN,X))
#define LH_CRITICAL(X) LH_LOG((PK_LOGLEVEL_CRITICAL,X))

class CPKLogImp;
class PKLog_API CPKLog
{
public:
	CPKLog();
	~CPKLog();
	//设置日志输出文件名，也作为日志类别标识，不调用此方法默认为General
	bool SetLogFileName(const char *szLogFileName = NULL);  
	void LogMessage(int nLogLevel, const char *szFormat, ...); //记录一条日志
	void LogErrMessage(int nErrCode, const char *szFormat, ...);  //记录一条错误日志
	void LogHexMessage(int nLogLevel, const char *szHexBuf, int nHexBufLen, const char *szFormat, ...); // 记录日志, 日志后包含16进制数据
private:
	CPKLogImp*	m_pPKLogImp;
};

#endif //!defined(_PKLOG_H_)


