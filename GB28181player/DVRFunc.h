//#include <afxtempl.h>
#include <map>
#include <vector>
#include <map>
#include <list>
#include <string>
#include <vector>
#include <windows.h>
#include "pklog/pklog.h"
#include "CatalogInfo.h"
#include "GB28181SIP.h"
#include "afxmt.h"





#include "jrtplib/jrtplib3/rtpsession.h"
#include"jrtplib/jrtplib3/rtpsourcedata.h"
#include "jrtplib/jrtplib3/rtpsessionparams.h"
#include "jrtplib/jrtplib3/rtpudpv4transmitter.h"
#include "jrtplib/jrtplib3/rtpipv4address.h"
#include "jrtplib/jrtplib3/rtptimeutilities.h"
#include "jrtplib/jrtplib3/rtppacket.h"

#ifdef  __cplusplus
extern "C"
{
#include "sdl2/SDL.h"
#include "libavcodec/avcodec.h"
#include "libavformat/avformat.h"
#include "libswscale/swscale.h"
#include "libavutil/imgutils.h"
}
#endif //  __cplusplus
using namespace std;

typedef int(*ReadBufferCallBack)(void *opaque, uint8_t *buf, int buf_size);

typedef	 struct	_PKGB281_STREAM
{
	AVFormatContext	 *pFormatCtx; //输入上下文
	int				 nAudioIndex, nVideoIndex;
	AVCodecContext	 *pCodecCtx;   //解码器上下文
	AVCodec			 *pCodec;      //解码器
	AVFrame			 *pFrame, *pFrameYUV;  //解码后的rgb和yuv的图像  控件播放只需要YUV
	AVPacket		 *packet;
	unsigned char *out_buffer;
	int y_size;
	int ret, got_picture;
	struct SwsContext *img_convert_ctx;
	int screen_w = 0, screen_h = 0;   //视频的长宽
	SDL_Window *screen;
	SDL_Renderer* sdlRenderer;
	SDL_Texture* sdlTexture;
	SDL_Rect sdlRect;
	SDL_Event  event;
	_PKGB281_STREAM()
	{
		memset(this, 0, sizeof(PKGB281_STREAM));
	}
}PKGB281_STREAM;

typedef struct
{
	long nLoginID;
	char* szChannel;
	HWND hWnd;
	long nCodeFlow;
	long nPlayID;
	string token;
}thread_info;

typedef struct
{
	unsigned length;
	uint8_t *buf;
}PacketNode_t;


typedef struct
{
	string ipchannel;
	long playid;
	string token;
}playInfo;

HANDLE m_hRecvThread;//接受流线程
CCriticalSection  m_cs;//锁
std::map<string, std::map<int, std::list<PacketNode_t>>> m_ip_channel_pack; //保存流数据
std::map<string, std::list<string>> m_ip_channels;//收到的设备信息，每个ip下对应多个通道
vector<playInfo> v_playInfos;	//正在播放的信息
CPKLog PKLog;


std::vector<std::string> split(const std::string& input, const char *delim) {
	std::vector<std::string> result;
	char *p = NULL;
	char *pRecv = strtok_s(const_cast<char*>(input.c_str()), delim, &p);
	while (pRecv != NULL)
	{
		result.push_back(pRecv);
		pRecv = strtok_s(NULL, delim, &p);
	}
	return	result;
}

int ReadNetPacket(uint8_t *buf, int buf_size, void *pContext)
{
	int nsize = 0;
	std::vector<std::string> tokens_ = split((char*)pContext, "@");
	std::string ip = "192.168.10." + tokens_.at(0);
	int channel = atoi(tokens_.at(1).c_str());
	std::map<string, std::map<int, std::list<PacketNode_t>>>::iterator it = m_ip_channel_pack.find(ip);
	if (it == m_ip_channel_pack.end())
	{
		return -1;
	}
	std::map<int, std::list<PacketNode_t>>::iterator iter2 = it->second.find(channel);
	if (iter2 == it->second.end())
	{
		return -1;
	}
	m_cs.Lock();
	if (!iter2->second.empty())
	{
		list<PacketNode_t>::iterator itr = iter2->second.begin();
		for (; itr != iter2->second.end();)
		{
			if (nsize < buf_size)
			{
				int nToReadSize = min(buf_size - nsize, itr->length);

				if (nToReadSize < itr->length)
				{
					memcpy(buf + nsize, itr->buf, nToReadSize);
					nsize += nToReadSize;

					::memmove(itr->buf, itr->buf + nToReadSize, itr->length - nToReadSize);
					itr->length -= nToReadSize;
					break;
				}
				else
				{
					memcpy(buf + nsize, itr->buf, itr->length);
					nsize += itr->length;
				}
			}
			else
			{
				break;
			}

			delete[] itr->buf; //释放内存
			iter2->second.erase(itr++);   //list删除item
		}
	}
	else
	{
		nsize = -1;  //表示没有数据可读
	}
	m_cs.Unlock();

	return nsize;
}

int ReleasePackets(string &ipchannel)
{
	std::vector<std::string> tokens_ = split(ipchannel, "@");
	std::string ip = "192.168.10." + tokens_.at(0);
	int channel = atoi(tokens_.at(1).c_str());
	std::map<string, std::map<int, std::list<PacketNode_t>>>::iterator it = m_ip_channel_pack.find(ip);
	if (it == m_ip_channel_pack.end())
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "no such ip's pack,ip:%s", ip.c_str());
		return -1;
	}
	std::map<int, std::list<PacketNode_t>>::iterator iter2 = it->second.find(channel);
	if (iter2 == it->second.end())
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "no such ip's channel's pack,channel:%d", channel);
		return -1;
	}
	m_cs.Lock();
	list<PacketNode_t>::iterator itr;
	for (itr = iter2->second.begin(); itr != iter2->second.end(); itr++) // 顺序遍历
	{
		delete[] itr->buf; //释放内存
	}
	iter2->second.clear();
	it->second.erase(iter2);
	m_cs.Unlock();
	PKLog.LogMessage(PK_LOGLEVEL_INFO, "erase pack succeed,ip:%s,channel:%d", ip.c_str(), channel);
	return 0;
}
int read_bufferto(void *opaque, uint8_t *buf, int buf_size)
{
	//读取内存流
	ASSERT(opaque != NULL);
	//CPlayStreamDlg* p_CPSDecoderDlg = (CPlayStreamDlg*)opaque;

	//TRACE("ReadBuf----- \n");
	int nBytes = ReadBuf((char*)buf, buf_size, opaque);
	return (nBytes > 0) ? buf_size : -1;

	return 0;
}
int ReadBuf(char* data, int len, void* pContext)
{
	int data_to_read = len;
	char * pReadPtr = data;

	while (1)
	{
		int nRead = ReadNetPacket((uint8_t*)pReadPtr, data_to_read, pContext);
		if (nRead < 0)
		{
			Sleep(10);
			continue;
		}
		pReadPtr += nRead;
		data_to_read -= nRead;
		if (data_to_read > 0)
		{
			Sleep(10);
			continue;
		}
		break;
	}

	return (data_to_read > 0) ? -1 : len;
}
void mycallback(void *user, void *data){
	CCatalogInfo* info = (CCatalogInfo*)data;
	m_ip_channels[info->PlatformAddr].push_back(info->DeviceID);
}
DWORD WINAPI RTPRecvThread(void *p)
{
	RTPSession session;
	RTPSessionParams sessionparams;
	sessionparams.SetOwnTimestampUnit(1.0 / 90000.0);
	RTPUDPv4TransmissionParams transparams;
	transparams.SetPortbase(6000); //读配置文件

	int oldBufSize = transparams.GetRTPReceiveBuffer();
	transparams.SetRTPReceiveBuffer(oldBufSize * 2);
	int status = session.Create(sessionparams, &transparams);

	int newBufSize = transparams.GetRTPReceiveBuffer();
	int oldBufSizec = transparams.GetRTCPReceiveBuffer();
	transparams.SetRTCPReceiveBuffer(oldBufSizec * 2);
	int newBufSizec = transparams.GetRTCPReceiveBuffer();

	while (1)
	{
#ifndef RTP_SUPPORT_THREAD
		int error_status = session.Poll();
#endif // RTP_SUPPORT_THREAD

		session.BeginDataAccess();
		if (session.GotoFirstSourceWithData())
		{
			do
			{
				RTPPacket *pack;
				RTPSourceData *rtpsource;
				rtpsource = session.GetCurrentSourceInfo();
				const RTPIPv4Address *addr = (const RTPIPv4Address *)(rtpsource->GetRTPDataAddress());
				uint32_t ip = addr->GetIP();
				uint32_t  host_ip = ntohl(ip);
				struct in_addr addr1;
				memcpy(&addr1, &host_ip, 4);
				string p = inet_ntoa(addr1);

				while ((pack = session.GetNextPacket()) != NULL)
				{
					int nPayType = pack->GetPayloadType();
					int nLen = pack->GetPayloadLength();
					unsigned char *pPayData = pack->GetPayloadData();
					int nPackLen = pack->GetPacketLength();
					unsigned char *pPackData = pack->GetPacketData();
					int csrc_cont = pack->GetCSRCCount();
					int ssrc = pack->GetSSRC();
					int nTimestamp = pack->GetTimestamp();
					int nSeqNum = pack->GetSequenceNumber();

#if 0
					Writebuf((char*)pPayData, nLen);
#else			
					m_cs.Lock();
					//if (pThisDlg->m_packetList.size() < MAX_PACKET_COUNT)
					{
						PacketNode_t  temNode;
						temNode.length = nLen;
						temNode.buf = new uint8_t[nLen];
						memcpy(temNode.buf, pPayData, nLen);

						m_ip_channel_pack[p][ssrc].push_back(temNode); //存包列表
					}
					m_cs.Unlock();
#endif

					session.DeletePacket(pack);
				}
			} while (session.GotoNextSourceWithData());
		}
		else
		{
			Sleep(10);
		}
		session.EndDataAccess();

		Sleep(1);
	}
	session.Destroy();

	TRACE("RTPRecvThread end! \n");
	return 0;
}

class CDVRFunc
{
private:
	

public:
	CDVRFunc(){}
	virtual ~CDVRFunc(){}
	
	// 向设备注册，返回注册ID
	long nInit()
	{
		return 0;
	}

	// 向设备注销
	long nlogin(std::string localip, std::string localport, long &nloginID)
	{
		return 0;
	}

	//---初始化SDK，插件可以在此接口中处理初始化的工作
	long VideoInitSDK()
	{
		return 0;
	}

	//---退出SDK，插件可以在此接口中处理资源释放的工作
	long VideoExitSDK()
	{
		return 0;
	}

	// 连接视频到某一窗口，返回播放ID
	long nstartplay(long &nLoginID, char* szChannel, HWND hWnd, long nCodeFlow, long &nPlayID)
	{
		return 0;
	}

	// 断开实时播放连接
	long nstopplay(long &nPlayID)
	{
		return 0;
	}

	// 在实时播放过程中抓拍图片
	long VideoRealPlayCapturePicture(long nPlayID, char* pszFileName, long nFileNameSize, long* pnPictureFormat)
	{
		return 0;
	}
};
 