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
#define PK_LOGLEVEL_DEBUG					0x01	// ������Ϣ
#define PK_LOGLEVEL_INFO					0x02	// ��Ϣ
#define PK_LOGLEVEL_WARN					0x04	// ����
#define PK_LOGLEVEL_ERROR					0x08	// ������Ϣ
#define PK_LOGLEVEL_CRITICAL				0x10	// �ؼ�����
#define PK_LOGLEVEL_NOTICE					0x20	// �����ӡ��ע������
#define PK_LOGLEVEL_COMM					0x100	// ����ͨѶ���ü������������ͬ�У������ǰ�����ϵ
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
	//������־����ļ�����Ҳ��Ϊ��־����ʶ�������ô˷���Ĭ��ΪGeneral
	bool SetLogFileName(const char *szLogFileName = NULL);  
	void LogMessage(int nLogLevel, const char *szFormat, ...); //��¼һ����־
	void LogErrMessage(int nErrCode, const char *szFormat, ...);  //��¼һ��������־
	void LogHexMessage(int nLogLevel, const char *szHexBuf, int nHexBufLen, const char *szFormat, ...); // ��¼��־, ��־�����16��������
private:
	CPKLogImp*	m_pPKLogImp;
};

#endif //!defined(_PKLOG_H_)


