/* Copyright [c] 2017-2027 By www.chungen90.com Allrights Reserved */
#ifndef GB_28181_SIP_H
#define GB_28181_SIP_H
#include <string>
#include "SipHead.h"


#if defined(GB28181SIP_EXPORTS)
#define GB28181SIP_API __declspec(dllexport)
#else
#define GB28181SIP_API __declspec(dllimport)
#endif

class GB28181SIP_API GB28181SIP
{
public:
	static bool  Init(std::string concat, int loglevel);

	static  void RegisterHandler(HandlerType handleType, void(callback)(void * user, void *data), void *user = nullptr);

	static std::string Invite(CMediaContext mediaContext);

	static void QueryRecordInfo(CMediaContext mediaContext);
	static bool Bye(std::string token);

	static void QueryCatalogInfo(const std::string& platformid);
};

#endif