#ifndef SIP_HEAD_H
#define SIP_HEAD_H
#define MEDIA_CONTEXT_H

#include<string>
using namespace std;

enum HandlerType
{
	Register= 1,
	KeepAlive = 2,
	RecvCatalog = 3,
	RecvStatus = 4,
	RecvRecordInfo = 5
};

enum StreamRequiredType
{
	Play = 0,
	Playback =1,
	Download = 2
};

class CMediaContext
{
public:
	explicit CMediaContext(std::string requestUrl)
		: requestUrl(requestUrl)
		, recvAddr("")
		, recvPort(-1)
		, senderAddr("")
		, deviceId("")
	{
		const int start = requestUrl.find_first_of(":");
		const int end = requestUrl.find_first_of("@");
		deviceId = requestUrl.substr(start + 1, end - start -1);
		streamRequiredType = Play;

	}

	std::string GetDeviceId() const
	{
		return deviceId;
	}

	void SetRecvAddress(std::string recvAddr)
	{
		this->recvAddr = recvAddr;
	}

	std::string GetRecvAddress() const
	{
		return recvAddr;
	}

	void SetRecvPort(int recvPort)
	{
		this->recvPort = recvPort;
	}

	int  GetRecvPort() const
	{
		return recvPort;
	}
	std::string GetRequestUrl() const
	{
		return requestUrl;
	}

	std::string GetStartTime() const
	{
		return startTime;
	}

	std::string GetEndTime() const
	{
		return endTime;
	}

	void SetTime(std::string startTime, std::string endTime)
	{
		this->startTime = startTime;
		this->endTime =endTime;
	}

	void SetDeviceId(std::string deviceId)
	{
		this->deviceId = deviceId;	
	}

	StreamRequiredType GetStreamType() const
	{
		return streamRequiredType;
	}

	void SetStreamType(StreamRequiredType streamRequiredType)
	{
		this->streamRequiredType = streamRequiredType;
	}
private:

	std::string requestUrl;
	std::string recvAddr;
	unsigned short recvPort;
	std::string senderAddr;	
	std::string deviceId;
	std::string startTime;
	std::string endTime;
	StreamRequiredType  streamRequiredType;
};

class RecordInfo
{
public:
	RecordInfo()
	{		
	}

	std::string DeviceId;
	std::string StartTime;
	std::string EndTime;
	std::string Name;
};
#endif