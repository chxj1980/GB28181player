/**************************************************************
 *  Filename:    DVRFunc.cpp
 *  Copyright:   Shanghai Peak InfoTech Co., Ltd.
 *

**************************************************************/

#include "stdafx.h"
#include "DVRFunc.h"
#include "h264.h"
//#include "tinyxml/tinyxml.h"


#include "video/errcode_video.h"
#include "video/VideoPlugin.h"
#include "pkcomm/pkcomm.h"
#include "pklog/pklog.h"
#include "ace/Date_Time.h"
#include "Resource.h"
#include <string> 
#include<iostream>
#include<algorithm>
#include "afxmt.h"
#include "CG28181Server.h"
#include "CGCatalogInfo.h"

#include "jrtplib/jrtplib3/rtpsession.h"
#include"jrtplib/jrtplib3/rtpsourcedata.h"
#include "jrtplib/jrtplib3/rtpsessionparams.h"
#include "jrtplib/jrtplib3/rtpudpv4transmitter.h"
#include "jrtplib/jrtplib3/rtpipv4address.h"
#include "jrtplib/jrtplib3/rtptimeutilities.h"
#include "jrtplib/jrtplib3/rtppacket.h"

CPKLog PKLog;
using namespace jrtplib;
using   namespace   std;
using namespace chungen::sip::server;

#pragma warning(disable: 4996)

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define DVRLOGFILENAME				"DVRUNV"
//#define PLAYM4_INITPLAYID			99					// ���ز���ID
#define QUERY_PAGE_NUM				30					// ��Դ��ѯ��¼��
#define MAX_CAMERA_COUNT			1024				// ���֧�ֵ�����ͷ����
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define DEMO_QUERY_PAGE_NUM			30					//��ѯ��ҳ��	

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


HANDLE m_hRecvThread;//�������߳�
CCriticalSection  m_cs;//��
std::map<string, std::map<int, std::list<PacketNode_t>>> m_ip_channel_pack; //����������
std::map<string, std::list<string>> m_ip_channels;//�յ����豸��Ϣ��ÿ��ip�¶�Ӧ���ͨ��
vector<playInfo> v_playInfos;	//���ڲ��ŵ���Ϣ


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
	std::string ip ="192.168.10."+ tokens_.at(0);
	int channel = atoi(tokens_.at(1).c_str());
	std::map<string,std::map<int, std::list<PacketNode_t>>>::iterator it = m_ip_channel_pack.find(ip);
	if (it == m_ip_channel_pack.end())
	{
		return -1;
	}
	std::map<int, std::list<PacketNode_t>>::iterator iter2 = it->second.find(channel);
	if (iter2==it->second.end())
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

			delete[] itr->buf; //�ͷ��ڴ�
			iter2->second.erase(itr++);   //listɾ��item
		}
	}
	else
	{
		nsize = -1;  //��ʾû�����ݿɶ�
	}
	m_cs.Unlock();

	return nsize;
}

int   ReleasePackets(string &ipchannel)
{	
	std::vector<std::string> tokens_ = split(ipchannel, "@");
	std::string ip = "192.168.10."+tokens_.at(0);
	int channel = atoi(tokens_.at(1).c_str());
	std::map<string, std::map<int, std::list<PacketNode_t>>>::iterator it = m_ip_channel_pack.find(ip);
	if (it == m_ip_channel_pack.end())
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "no such ip's pack,ip:%s",ip.c_str());
		return -1;
	}
	std::map<int, std::list<PacketNode_t>>::iterator iter2 = it->second.find(channel);
	if (iter2 == it->second.end())
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "no such ip's channel's pack,channel:%d",channel);
		return -1;
	}
	m_cs.Lock();
	list<PacketNode_t>::iterator itr;
	for (itr = iter2->second.begin(); itr != iter2->second.end(); itr++) // ˳�����
	{
		delete[] itr->buf; //�ͷ��ڴ�
	}
	iter2->second.clear();
	it->second.erase(iter2);
	m_cs.Unlock();
	PKLog.LogMessage(PK_LOGLEVEL_INFO, "erase pack succeed,ip:%s,channel:%d", ip.c_str(),channel);
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
	CGCatalogInfo* info = (CGCatalogInfo*)data;
	m_ip_channels[info->PlatformAddr].push_back(info->DeviceID);
}



extern CDVRFunc g_DVRFunc;

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
//ץͼ�ص�����
void CALLBACK DisplayCBFun(long nPort,char * pBuf,long nSize,long nWidth,long nHeight,long nStamp,long nType,long nReceaved)
{
	//ת���������ȽϺ�ʱ��������뱣��ͼƬ���벻Ҫ���ã�
	//PlayM4_ConvertToBmpFile(pBuf,nSize,nWidth,nHeight,nType,g_strLocalPicFileName.GetBuffer(0));
}

int read_bufferto(void *opaque, uint8_t *buf, int buf_size)
{
	//��ȡ�ڴ���
	ASSERT(opaque != NULL);
	//CPlayStreamDlg* p_CPSDecoderDlg = (CPlayStreamDlg*)opaque;

	//TRACE("ReadBuf----- \n");
	int nBytes = ReadBuf((char*)buf, buf_size, opaque);
	return (nBytes > 0) ? buf_size : -1;

	return 0;
}


int thread_exit = 0;
#define SFM_REFRESH_EVENT  (SDL_USEREVENT + 1)
#define SFM_BREAK_EVENT    (SDL_USEREVENT + 2)

//#define SDL_NO_CREATE_THREAD   //�Ƿ�Ϊsdl����һ���߳�  û�к궨�� �ʹ���һ���߳�
int sfp_refresh_thread(void *opaque){
	thread_exit = 0;
	while (!thread_exit) {
		SDL_Event event;
		event.type = SFM_REFRESH_EVENT;
		SDL_PushEvent(&event);
	}
	thread_exit = 0;
	//Break
	SDL_Event event;
	event.type = SFM_BREAK_EVENT;
	SDL_PushEvent(&event);
	return 0;
}

void CALLBACK RunInfoCBFun(IN const USER_LOGIN_ID_INFO_S *pstUserLoginIDInfo, IN ULONG ulRunInfoType, IN VOID *pParam)
{
	PKLog.LogMessage(PK_LOGLEVEL_INFO, "�յ��ص���Ϣ���ص����ͣ�%u", ulRunInfoType);
	if(ulRunInfoType == XP_RUN_INFO_DOWN_RTSP_PROTOCOL)
	{
		XP_RUN_INFO_EX_S*  pDownInfo = (XP_RUN_INFO_EX_S*)pParam;
		if(pDownInfo != NULL)
		{
			if(pDownInfo->ulErrCode == ERR_XP_RTSP_COMPLETE)
			{
				PDOWNLOAD_INFO pDownloadInfo = NULL;
				bool bFound = g_DVRFunc.GetDownloadInfoByDownloadCode(pDownInfo->szPortCode, pDownloadInfo);
				if(!bFound)
				{
					return;
				}

				pDownloadInfo->nDownPos = 100;
			}
		}
	}
}

/**
 *  $(��ȡ�ַ����е���һ��Ԫ�أ��һ���������).
 *
 *  @param  -[in,out]  CString&  strSrc: [Դ������]
 *  @param  -[in]  TCHAR  nSep: [�ָ���]
 *  @return $(Ŀ�껺����).
 *
 *  @version  06/21/2008  xulizai  Initial Version.
 */
CString CDVRFunc::GetNextToken(CString &strSrc, TCHAR nSep)
{
	long nSlash = strSrc.Find(nSep);

	CString strToken;
	if (nSlash < 0)
	{
		strToken = strSrc;
		strSrc.Empty();
	}
	else
	{
		strToken = strSrc.Left(nSlash);
		strSrc = strSrc.Right(strSrc.GetLength() - nSlash - 1);
	}

	return strToken;
}

int API_TimeToStringEX(char* strDateStr,const time_t &timeData)
{
    char chTmp[100];
    memset(chTmp,0,sizeof(chTmp));
    struct tm *p;
    p = localtime(&timeData);
    p->tm_year = p->tm_year + 1900;
    p->tm_mon = p->tm_mon + 1;
	
    sprintf(chTmp,"%04d-%02d-%02d %02d:%02d:%02d",p->tm_year, p->tm_mon, p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
    //strDateStr = chTmp;
	strncpy(strDateStr, chTmp, IMOS_TIME_LEN);
    return 0;
}

int API_StringToTimeEX(const char* strDateStr,time_t &timeData)
{
    char *pBeginPos = (char*)strDateStr;
    char *pPos = strstr(pBeginPos,"-");
    if(pPos == NULL)
    {
        return -1;
    }
    int iYear = atoi(pBeginPos);
    int iMonth = atoi(pPos + 1);
    pPos = strstr(pPos + 1,"-");
    if(pPos == NULL)
    {
        return -1;
    }
    int iDay = atoi(pPos + 1);
    int iHour=0;
    int iMin=0;
    int iSec=0;
    pPos = strstr(pPos + 1," ");
    //Ϊ�˼�����Щû��ȷ��ʱ�����
    if(pPos != NULL)
    {
        iHour=atoi(pPos + 1);
        pPos = strstr(pPos + 1,":");
        if(pPos != NULL)
        {
            iMin=atoi(pPos + 1);
            pPos = strstr(pPos + 1,":");
            if(pPos != NULL)
            {
                iSec=atoi(pPos + 1);
            }
        }
    }
	
    struct tm sourcedate;
    memset((void*)&sourcedate,0,sizeof(sourcedate));
    sourcedate.tm_sec = iSec;
    sourcedate.tm_min = iMin; 
    sourcedate.tm_hour = iHour;
    sourcedate.tm_mday = iDay;
    sourcedate.tm_mon = iMonth - 1; 
    sourcedate.tm_year = iYear - 1900;
    timeData = mktime(&sourcedate);  
    return 0;
}

ULONG CDVRFunc::CharToWideChar(LPSTR pChar, ULONG ulCharSize, BOOL_T bIsUTF8, LPCWSTR pWideChar)
{
    LONG lOrigsize = 0;
    LONG lConvertedChars = 0;
	LONG lCodePage = CP_ACP;	
    if (NULL == pChar)
    {
        return ERR_COMMON_INVALID_PARAM;
    }
	
    lOrigsize = (LONG) strlen((CHAR *) pChar);       /* ��ȡ�ַ�������*/
    if (0 == lOrigsize)
    {
        memset((void*)pWideChar, 0, ulCharSize);
        return ERR_COMMON_SUCCEED;
    }
	
	if (BOOL_TRUE == bIsUTF8)
	{
		lCodePage = CP_UTF8;
	}
	else
	{
		lCodePage = CP_ACP;
	}
	
    /* ��pcFilePathת��խ�ַ�*/
    lConvertedChars = MultiByteToWideChar(
        lCodePage,                                 /* code page */ 
        0,                                         /* performance and mapping flags */ 
        (LPCSTR) pChar,                            /* wide-character string */ 
        lOrigsize,                                 /* number of chars in string. */ 
        (LPWSTR)pWideChar,                         /* buffer for new string */ 
        (LONG) ulCharSize - 1                      /* size of buffer */ 
        );
	
    if (0 == lConvertedChars)
    {
        return ERR_COMMON_FAIL;
    }
	
    return ERR_COMMON_SUCCEED;
}

ULONG CDVRFunc::WideCharToChar(LPCWSTR pWideChar, ULONG ulCharSize, BOOL_T bIsUTF8, LPSTR pChar)
{
    LONG lOrigsize = 0;
    LONG lConvertedChars = 0;
	LONG lCodePage = CP_ACP;	
    if (NULL == pWideChar)
    {
        return ERR_COMMON_INVALID_PARAM;
    }
	
    lOrigsize = (LONG) wcslen((WCHAR *) pWideChar);       /* ��ȡ�ַ�������*/
    if (0 == lOrigsize)
    {
        memset(pChar, 0, ulCharSize);
        return ERR_COMMON_SUCCEED;
    }
	
	if (BOOL_TRUE == bIsUTF8)
	{
		lCodePage = CP_UTF8;
	}
	else
	{
		lCodePage = CP_ACP;
	}
	
    /* ��pcFilePathת��խ�ַ�*/
    lConvertedChars = WideCharToMultiByte(
        lCodePage,                                      /* code page */ 
        WC_COMPOSITECHECK|WC_DEFAULTCHAR,               /* performance and mapping flags */ 
        (LPCWSTR) pWideChar,                            /* wide-character string */ 
        lOrigsize,                                      /* number of chars in string. */ 
        pChar,                                          /* buffer for new string */ 
        (LONG) ulCharSize - 1,                          /* size of buffer */ 
        0,                                              /* default for unmappable chars */ 
        0                                               /* set when default char used */ 
        );
	
    if (0 == lConvertedChars)
    {
        return ERR_COMMON_FAIL;
    }
    pChar[lConvertedChars] = '\0';
	
    return ERR_COMMON_SUCCEED;
}
//���ӵ��쳣�ص�����
void pIMOSSetSDKErrInfo(LPVOID  lpUserID, INT32 dwType, LPVOID lpExpHandle, LPVOID  lpUserData)
{
	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "loginID:%p,NETDEVException type %d,exception handle:%p", lpUserID, dwType, lpExpHandle);
}

void CDVRFunc::ConvertUTF8ToUnicode(LPSTR pSrcChar, LPSTR pcDestChar, int length)
{
    WCHAR *pWchar;
    pWchar = (WCHAR *)malloc(length * sizeof(WCHAR));
    if (NULL == pWchar)
    {
        return;
    }
    memset(pWchar, 0, length * sizeof(WCHAR));
	
    CharToWideChar(pSrcChar, length, BOOL_TRUE, pWchar);
    WideCharToChar(pWchar, length, BOOL_FALSE, pcDestChar);
    if (NULL != pWchar)
    {
        free(pWchar);
    }
}

bool CDVRFunc::IsDeviceLoggedIn(char* szDeviceIP, long &nLoginID, PDEVICE_INFO &pDeviceInfo)
{
	bool bLogged = false;
	if (m_mapDeviceInfo.size() == 0){
		return false;
	}
	for (auto it : m_mapDeviceInfo){
		PDEVICE_INFO pDevice = &(it.second);
		if (strcmp(pDevice->szDeviceIP, szDeviceIP) == 0){
			pDeviceInfo = pDevice;
			nLoginID = it.first;
			bLogged = true;
			break;
		}
	}
	return bLogged;
}

bool CDVRFunc::GetDeviceByLoginID(long nLoginID, PDEVICE_INFO &pDeviceInfo)
{
	bool bFound = false;

	DEVICEINFOMAP::iterator it = m_mapDeviceInfo.find(nLoginID);
	if(it != m_mapDeviceInfo.end())
	{
		bFound = true;	
		pDeviceInfo = &(it->second);
	}
	else
	{
		bFound = false;
	}
	return bFound;
}

bool CDVRFunc::GetPlayInfoByPlayID(long nPlayID, PPLAY_INFO &pPlayInfo)
{
	bool bFound = false;

	PLAYINFOMAP::iterator it = m_mapPlayInfo.find(nPlayID);
	if(it != m_mapPlayInfo.end())
	{
		bFound = true;	
		pPlayInfo = &(it->second);
	}
	else
	{
		bFound = false;
	}

	return bFound;
}

bool CDVRFunc::GetDownloadInfoByDownloadID(long nDownloadID, PDOWNLOAD_INFO &pDownloadInfo)
{
	bool bFound = false;

	DOWNLOADMAP::iterator it = m_mapDownload.find(nDownloadID);
	if(it != m_mapDownload.end())
	{
		bFound = true;	
		pDownloadInfo = &(it->second);
	}
	else
	{
		bFound = false;
	}

	return bFound;
}

bool CDVRFunc::GetDownloadInfoByDownloadCode(char* szDownloadCode, PDOWNLOAD_INFO &pDownloadInfo)
{
	bool bFound = false;

	DOWNLOADMAP::iterator it = m_mapDownload.begin();
	for(; it != m_mapDownload.end(); it++)
	{
		PDOWNLOAD_INFO pDown = &(it->second);
		if(strcmp(pDown->szDownload, szDownloadCode) == 0)
		{
			pDownloadInfo = pDown;
			bFound = true;
			break;
		}
	}
	return bFound;
}

int CDVRFunc::FindWindowNotUsed(PDEVICE_INFO pDeviceInfo)
{

	return 0;
}

CDVRFunc::CDVRFunc()
{
	m_nDownloadIndex = 0;
	m_mapDeviceInfo.clear();
	m_mapDownload.clear();
	m_mapPlayInfo.clear();
	m_mapPlaybackId2TotalTime.clear();
	m_mapLoginid2Handle.clear();
	m_mapPlayid2Handle.clear();
}

CDVRFunc::~CDVRFunc()
{

}
// ��ȡ����İ汾��
long CDVRFunc::VideoGetVersionNumber()
{
	return 5001;//VIDEO_CURRENT_VERSION;
}

DWORD WINAPI RTPRecvThread(void *p)
{
	RTPSession session;
	RTPSessionParams sessionparams;
	sessionparams.SetOwnTimestampUnit(1.0 / 90000.0);
	RTPUDPv4TransmissionParams transparams;
	transparams.SetPortbase(6000); //�������ļ�

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

						m_ip_channel_pack[p][ssrc].push_back(temNode); //����б�
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
//{
//	char* a= (char*)p;
//	char recvbuf[4 * 1024] = { 0 };
//	SOCKET  socket1;
//	SOCKADDR_IN client;//����һ����ַ�ṹ��
//	int len_client = sizeof(client);
//	int	receive_bytes = 0;
//
//	socket1 = socket(AF_INET, SOCK_DGRAM, 0);
//
//	client.sin_family = AF_INET;
//	client.sin_addr.s_addr = htonl(INADDR_ANY);
//	client.sin_port = htons(6000);
//
//	if (bind(socket1, (struct sockaddr*)&client, sizeof(client)) == -1)
//	{
//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Bind to local machine error.\n");
//		return -2;
//	}
//	else
//	{
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Bind to local machine.\n");
//	}
//
//	//���ý��ճ�ʱ���������û�����ݣ����һֱ����recvfrom���պ���
//	int timeout = 2000; //��λ������
//	if (setsockopt(socket1, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
//	{
//		return -3;
//	}
//
//	//���ý��ջ�������С, ���һ����Լ��ٶ���Ƶ��
//	int nRecvBuf = 512 * 1024;
//	if (setsockopt(socket1, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int)) == SOCKET_ERROR)
//	{
//		return -4;
//	}
//
//	RTP_FIXED_HEADER * rtp_hdr = NULL;
//	int rtpMarkerBit;
//	unsigned char cFrameType = '0';
//
//	unsigned char temp_buffer[1500];
//	memset(temp_buffer, 0, 1500);
//	int temp_size = 0;
//
//	//unsigned char * frame_buffer = (unsigned char *)malloc(500 * 1024); //�洢������һ֡����
//	//int frame_size = 0;
//
//	while (1)
//	{
//		receive_bytes = recvfrom(socket1, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&client, &len_client);
//		if (receive_bytes <= 0)
//		{
//			if (WSAGetLastError() == 10060) //���ճ�ʱ
//			{
//				Sleep(1);
//				continue;
//			}
//			break;
//		}
//
//		rtp_hdr = (RTP_FIXED_HEADER*)&recvbuf[0];
//		/*PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "�汾�� : %d\n", rtp_hdr->version);
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "������־λ : %d\n", rtp_hdr->marker);
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "��������:%d\n", rtp_hdr->payload);
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "����   : %d \n", htons(rtp_hdr->seq_no));
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "ʱ��� : %d\n", htonl(rtp_hdr->timestamp));
//		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "ͬ����ʶ��   : %d\n", htonl(rtp_hdr->ssrc));*/
//
//
//		memcpy(temp_buffer, recvbuf + 12, receive_bytes - 12);
//		temp_size = receive_bytes - 12;
//
//#if 0
//		Writebuf((char*)temp_buffer, temp_size);
//#else			
//		m_cs.Lock();
//		{
//
//			PacketNode_t  temNode;
//			temNode.length = temp_size;
//			temNode.buf = new uint8_t[temp_size];
//			memcpy(temNode.buf, temp_buffer, temp_size);
//			m_packetList.push_back(temNode); //����б�
//		}
//		m_cs.Unlock();
//#endif
//
//	}
//
//	closesocket(socket1);
//}
//��ʼ��GB28181
long CDVRFunc::VideoInitSDK()
{

	//��ʼ��ffmpeg sdl�Ŀ�
	av_register_all();
	avformat_network_init();

	//��ʼ��sdl�Ŀ�
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER)) 
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Could not initialize SDL - %s\n", SDL_GetError());
		return -1;
	}

	PKLog.LogMessage(PK_LOGLEVEL_NOTICE, " GB28181 VideoInitSDK success");
	
	//����һ��udp��server  �ȴ�������������
	DWORD threadID = 0;
	char* ip = "192.168.10.119";
	m_hRecvThread = CreateThread(NULL, 0, RTPRecvThread, 0, 0, &threadID);
	
	return VIDEO_SUCCESS;	
}

// �˳�SDK����������ڴ˽ӿ��д�����Դ�ͷŵĹ���
long CDVRFunc::VideoExitSDK()
{
	//long lRet=0;
	//CString strTemp;
	//strTemp.LoadString(IDS_STRING103);
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));

	//int nCount = m_mapDeviceInfo.size();

	//DEVICEINFOMAP::iterator it = m_mapDeviceInfo.begin();
	//for(; it != m_mapDeviceInfo.end(); it++)
	//{
	//	long nLoginID = it->first;
	//	PDEVICE_INFO pDevice = &(it->second);

	//	if(nLoginID >= 0)
	//	{
	//		VideoLogout(nLoginID);	
	//		//it = m_mapDeviceInfo.begin();
	//		//memset(&pDevice->stLoginInfo, 0, sizeof(LOGIN_INFO_S));
	//	}
	//}
	///*ע������ԭ���ǣ��ڶര�ڲ�����Ƶ��ʱ�򣬵�¼��Ϣ��������Ϣ�ǹ���ģ����Բ���clear��¼��Ϣ��������Ϣ 
	//����Ȫ 2015.1.26�޸�
	//*/
	////m_mapDeviceInfo.clear();
	////m_mapDownload.clear();
	//strTemp.LoadString(IDS_STRING104);
	//PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0));
	//BOOL res=NETDEV_Cleanup();
	//if (!res)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV ExitSDK NETDEV_Cleanup Fail,Error code:%d", iError);
	//	return iError;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV ExitSDK NETDEV_Cleanup Success");
	return VIDEO_SUCCESS;
}


// ���豸ע�ᣬ����ע��ID
long CDVRFunc::VideoLogin(char* pszDeviceIP, char *szDevicePort, char *szUserName, char *szPassword, char* szExtParam, long &nLoginID)
{
	
	string localSipPlatFormId = "34020000002000000001";
	string localAddress = string(pszDeviceIP);
	int localSipPort = atoi(szDevicePort);
	const auto localcontact = "SIP:" + localSipPlatFormId +
		"@" + localAddress + ":" + to_string(localSipPort);

	if (CG28181Server::Init(localcontact, 3))
	{
		CG28181Server::RegisterHandler(Register, nullptr);
		CG28181Server::RegisterHandler(KeepAlive, nullptr);
		CG28181Server::RegisterHandler(RecvCatalog, mycallback, nullptr);
		CG28181Server::RegisterHandler(RecvRecordInfo, nullptr);
		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Sip Registered succeed!");
	}
	else
	{
		PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Sip Registered Failed!");
	}
	

	
	long *pLong = new long();
	nLoginID = (long)pLong;
	return nLoginID;	
	return VIDEO_SUCCESS;
}

// ���豸ע��
long CDVRFunc::VideoLogout(long &nLoginID)
{
	
	return VIDEO_SUCCESS;
}

// Զ������
long CDVRFunc::VideoRebootDVR(long nLoginID)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
    return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

// Զ�̹ر�
long CDVRFunc::VideoShutDownDVR(long nLoginID)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
	return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

long lMyPlayID=0;

CString CDVRFunc::GetTimeStr() 
{ 
	SYSTEMTIME time;
	GetLocalTime(&time);
	CString year;
	CString month;
	CString day;
	year.Format(_T("%d"), time.wYear);
	month.Format(_T("%d"), time.wMonth);
	day.Format(_T("%d"), time.wDay);
	month = time.wMonth < 10 ? (_T("0") + month):month;
	day = time.wDay < 10 ? (_T("0") + day):day;
	CString strTime = year + _T("/") + month + _T("/") + day + _T(" ");

	CHAR* pTime = new CHAR[30];

	CString strFormat = _T("HH:mm:ss");

	GetTimeFormat(LOCALE_INVARIANT , LOCALE_USE_CP_ACP, &time, strFormat, pTime, 30);
	strTime += pTime;
	CString milliseconds;
	milliseconds.Format(_T("%d"), time.wMilliseconds);
	if ( time.wMilliseconds>=100)
	{
		strTime += _T(".") + milliseconds;
	}
	else if (time.wMilliseconds>=10 && time.wMilliseconds<100)
	{
		strTime += _T(".0") + milliseconds;
	}
	else
	{
		strTime += _T(".00") + milliseconds;
	}
	return strTime;

}
DWORD WINAPI SDL_PLAY_VEDIO(LPVOID message){
	thread_info infomation = *(thread_info*)message;
	long &nLoginID = infomation.nLoginID;
	char* szChannel=infomation.szChannel;
	HWND hWnd = infomation.hWnd;
	long nCodeFlow = infomation.nCodeFlow;
	long &nPlayID = infomation.nPlayID;
	string token = infomation.token;
	PKGB281_STREAM play_stream;
	//��������
	//����������Ϣ
	//���ҽ�����
	//����
	//sdl��ʾ
	AVDictionary *optionsDict = NULL;
	av_dict_set(&optionsDict, "probesize", "1024000", 0);      //50k̽����  ����̽�������ӳ�ʱ��
	av_dict_set(&optionsDict, "max_delay", "3000000", 0);    //����ӳ�ʱ��3s
	AVInputFormat* piFmt = NULL;
	////����Ǵ��ڴ��л�ȡ��Ƶ��
	if (0 == nCodeFlow)
	{
		if (read_bufferto)
		{
			play_stream.pFormatCtx = avformat_alloc_context();
			unsigned char *aviobuffer = (unsigned char *)av_malloc(32768);  //32768
			AVIOContext *avio = avio_alloc_context(aviobuffer, 32768, 0, szChannel, read_bufferto, NULL, NULL);   //���������� �û�����  �ص�ʱ��Ҫ			
			play_stream.pFormatCtx->pb = avio;
		}
	}

	int ret = -1;
	char szError[256] = { 0 };
	if ((ret = avformat_open_input(&play_stream.pFormatCtx, szChannel, 0, &optionsDict)) < 0)
		//if ((ret = avformat_open_input(&play_stream.pFormatCtx, NULL, 0, &optionsDict)) < 0)
	{
		av_make_error_string(szError, sizeof(szError), ret);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "AVFormatContext Could Not Open,Error:%s,ret:%d", szError, ret);
		return ret;
	}
	PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Input Stream AVFormatContext Open Success");
	if ((ret = avformat_find_stream_info(play_stream.pFormatCtx, 0)) < 0)
	{
		memset(szError, 0, sizeof(szError));
		av_make_error_string(szError, sizeof(szError), ret);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Fail find_stream_info,Error:%s,ret:%d", szError, ret);
		return ret;
	}
	int nStreams = play_stream.pFormatCtx->nb_streams;
	PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Find Straeams %d", nStreams);

	//������Ƶ��������
	//m_pVideo->nVideoIndex = av_find_best_stream(m_pFormatCtx, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
	for (int i = 0; i < nStreams; i++)
	{
		if (play_stream.pFormatCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
		{
			play_stream.nVideoIndex = i;
			break;    //��ʱ������Ƶ�ĵĴ���
		}
		if (play_stream.pFormatCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_AUDIO)
		{
			play_stream.nAudioIndex = i;
		}
	}
	//���ҽ����� ��ȡ����
	AVCodec *pCodec;
	AVCodecContext *pCodecCtx = play_stream.pFormatCtx->streams[play_stream.nVideoIndex]->codec;
	pCodec = avcodec_find_decoder(pCodecCtx->codec_id);
	PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Input Video type %s  typeid %d", pCodec->name, pCodec->id);

	if (avcodec_open2(pCodecCtx, pCodec, NULL) < 0){
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Could not open codec");
		return -1;
	}

	play_stream.pFrame = av_frame_alloc();   //���ٵ�ʱ��  ע���ͷ��ڴ�
	play_stream.pFrameYUV = av_frame_alloc();
	play_stream.out_buffer = (unsigned char *)av_malloc(av_image_get_buffer_size(AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height, 1));
	av_image_fill_arrays(play_stream.pFrameYUV->data, play_stream.pFrameYUV->linesize, play_stream.out_buffer, AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height, 1);


	play_stream.packet = (AVPacket *)av_malloc(sizeof(AVPacket));
	av_dump_format(play_stream.pFormatCtx, 0, "", 0);

	play_stream.img_convert_ctx = sws_getContext(pCodecCtx->width, pCodecCtx->height, pCodecCtx->pix_fmt,
		pCodecCtx->width, pCodecCtx->height, AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
	//׼��������ʾ
	//Ϊÿһ·�������Ƶ ��һ���߳�
	//sdl
	play_stream.screen_w = pCodecCtx->width;
	play_stream.screen_h = pCodecCtx->height;

	if (!hWnd)
	{
		play_stream.screen = SDL_CreateWindow("Simplest ffmpeg player's Window", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
			play_stream.screen_w, play_stream.screen_h,
			SDL_WINDOW_OPENGL);
	}
	else
	{
		play_stream.screen = SDL_CreateWindowFrom(hWnd);

	}
	if (!play_stream.screen) {
		printf("SDL: could not create window - exiting:%s\n", SDL_GetError());
		return -1;
	}

	play_stream.sdlRenderer = SDL_CreateRenderer(play_stream.screen, -1, 0);
	//IYUV: Y + U + V  (3 planes)
	//YV12: Y + V + U  (3 planes)
	play_stream.sdlTexture = SDL_CreateTexture(play_stream.sdlRenderer, SDL_PIXELFORMAT_IYUV, SDL_TEXTUREACCESS_STREAMING, pCodecCtx->width, pCodecCtx->height);

	play_stream.sdlRect.x = 0;
	play_stream.sdlRect.y = 0;
	play_stream.sdlRect.w = play_stream.screen_w;
	play_stream.sdlRect.h = play_stream.screen_h;

	//��ȡ��Ƶ֡  ��ʾ 
	while (true)
	{
		if (av_read_frame(play_stream.pFormatCtx, play_stream.packet) >= 0)
		{
			if (play_stream.packet->stream_index == play_stream.nVideoIndex)
			{
				ret = avcodec_decode_video2(pCodecCtx, play_stream.pFrameYUV, &play_stream.got_picture, play_stream.packet);
				if (ret < 0)
				{
					PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Decode Error.\n");
					return -1;
				}
				if (play_stream.got_picture)
				{
					//ת��ȥ����Ч����
					sws_scale(play_stream.img_convert_ctx, (const unsigned char* const*)play_stream.pFrame->data, play_stream.pFrame->linesize, 0, pCodecCtx->height,
						play_stream.pFrameYUV->data, play_stream.pFrameYUV->linesize);

					//SDL_UpdateTexture(sdlTexture, &sdlRect, pFrameYUV->data[0], pFrameYUV->linesize[0]);

					SDL_UpdateYUVTexture(play_stream.sdlTexture, NULL,
						play_stream.pFrameYUV->data[0], play_stream.pFrameYUV->linesize[0],
						play_stream.pFrameYUV->data[1], play_stream.pFrameYUV->linesize[1],
						play_stream.pFrameYUV->data[2], play_stream.pFrameYUV->linesize[2]);

					SDL_RenderClear(play_stream.sdlRenderer);
					SDL_RenderCopy(play_stream.sdlRenderer, play_stream.sdlTexture, NULL, NULL);
					SDL_RenderPresent(play_stream.sdlRenderer);
					SDL_Delay(20);
				}
			}
			av_free_packet(play_stream.packet);
			
		}
	}
	if (play_stream.pFormatCtx)
	{
		avformat_close_input(&play_stream.pFormatCtx);
		play_stream.pFormatCtx = NULL;
	}
	sws_freeContext(play_stream.img_convert_ctx);
	av_frame_free(&play_stream.pFrameYUV);
	av_frame_free(&play_stream.pFrame);
	
}
// ������Ƶ��ĳһ���� �˴���ͨ��Ӧ��Ϊ�豸��ID 
long CDVRFunc::VideoPlayVideo(long &nLoginID, char* szChannel, HWND hWnd, long nCodeFlow, long &nPlayID)
{
	//�÷���������˿�������
	std::vector<string> vec_ = split(szChannel, "@");
	string ip = "192.168.10."+vec_.at(0);
	string channel = "3402000000" + vec_.at(1);
	string localAddress = "192.168.10.223";
	int receivePort = 6000;
	string requestUrl = "sip:" + channel+"@"+ip+":5060";
	MediaContext mediaContext(requestUrl);
	mediaContext.SetRecvAddress(localAddress);
	mediaContext.SetRecvPort(receivePort);
	string token = CG28181Server::Invite(mediaContext);
	thread_info threadinfo = { nLoginID, szChannel, hWnd, nCodeFlow, nPlayID,token };
	HANDLE mainthread = CreateThread(NULL, 0, SDL_PLAY_VEDIO, &threadinfo, 0, NULL);
	////���һ�����ž����map
	playInfo info ;
	info.ipchannel = szChannel;
	info.playid = nPlayID;
	info.token = token;
	v_playInfos.push_back(info);
	//PKGB281_STREAM play_stream;
	////��������
	////����������Ϣ
	////���ҽ�����
	////����
	////sdl��ʾ
	//AVDictionary *optionsDict = NULL;
	//av_dict_set(&optionsDict, "probesize", "1024000", 0);      //50k̽����  ����̽�������ӳ�ʱ��
	//av_dict_set(&optionsDict, "max_delay", "3000000", 0);    //����ӳ�ʱ��3s
	//AVInputFormat* piFmt = NULL;
	//////����Ǵ��ڴ��л�ȡ��Ƶ��
	//if (0 == nCodeFlow)
	//{
	//	if (read_bufferto)
	//	{
	//		play_stream.pFormatCtx = avformat_alloc_context();
	//		unsigned char *aviobuffer = (unsigned char *)av_malloc(32768);  //32768
	//		AVIOContext *avio = avio_alloc_context(aviobuffer, 32768, 0, "192.168.10.119:1320000001", read_bufferto, NULL, NULL);   //���������� �û�����  �ص�ʱ��Ҫ
	//		//if (av_probe_input_buffer(avio, &piFmt, "", NULL, 0, 0) < 0)//̽����ڴ��л�ȡ����ý�����ĸ�ʽ
	//		//{
	//		//	TRACE("Error: probe format failed\n");
	//		//	return -1;
	//		//}
	//		//else {
	//		//	TRACE("input format:%s[%s]\n", piFmt->name, piFmt->long_name);

	//		//}
	//		play_stream.pFormatCtx->pb = avio;
	//		//m_pVideo->m_pBuff = aviobuffer;
	//	}
	//}

	//int ret = -1;
	//char szError[256] = { 0 };
	//if ((ret = avformat_open_input(&play_stream.pFormatCtx, szChannel, 0, &optionsDict)) < 0)
	////if ((ret = avformat_open_input(&play_stream.pFormatCtx, NULL, 0, &optionsDict)) < 0)
	//{
	//	av_make_error_string(szError, sizeof(szError), ret);
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "AVFormatContext Could Not Open,Error:%s,ret:%d", szError, ret);
	//	return ret;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Input Stream AVFormatContext Open Success");
	//if ((ret = avformat_find_stream_info(play_stream.pFormatCtx, 0)) < 0)
	//{
	//	memset(szError, 0, sizeof(szError));
	//	av_make_error_string(szError, sizeof(szError), ret);
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Fail find_stream_info,Error:%s,ret:%d", szError, ret);
	//	return ret;
	//}
	//int nStreams = play_stream.pFormatCtx->nb_streams;
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Find Straeams %d", nStreams);

	////������Ƶ��������
	////m_pVideo->nVideoIndex = av_find_best_stream(m_pFormatCtx, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
	//for (int i = 0; i < nStreams; i++)
	//{
	//	if (play_stream.pFormatCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
	//	{
	//		play_stream.nVideoIndex = i;
	//		break;    //��ʱ������Ƶ�ĵĴ���
	//	}
	//	if (play_stream.pFormatCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_AUDIO)
	//	{
	//		play_stream.nAudioIndex = i;
	//	}
	//}
	////���ҽ����� ��ȡ����
	//AVCodec *pCodec;
	//AVCodecContext *pCodecCtx = play_stream.pFormatCtx->streams[play_stream.nVideoIndex]->codec;
	//pCodec = avcodec_find_decoder(pCodecCtx->codec_id);
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "Input Video type %s  typeid %d", pCodec->name, pCodec->id);

	//if (avcodec_open2(pCodecCtx, pCodec, NULL) < 0){
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR,"Could not open codec");
	//	return -1;
	//}

	//play_stream.pFrame = av_frame_alloc();   //���ٵ�ʱ��  ע���ͷ��ڴ�
	//play_stream.pFrameYUV = av_frame_alloc();
	//play_stream.out_buffer = (unsigned char *)av_malloc(av_image_get_buffer_size(AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height, 1));
	//av_image_fill_arrays(play_stream.pFrameYUV->data, play_stream.pFrameYUV->linesize, play_stream.out_buffer,AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height, 1);


	//play_stream.packet = (AVPacket *)av_malloc(sizeof(AVPacket));
	//av_dump_format(play_stream.pFormatCtx, 0, "", 0);

	//play_stream.img_convert_ctx = sws_getContext(pCodecCtx->width, pCodecCtx->height, pCodecCtx->pix_fmt,
	//pCodecCtx->width, pCodecCtx->height, AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
	////׼��������ʾ
	////Ϊÿһ·�������Ƶ ��һ���߳�
	////sdl
	//play_stream.screen_w = pCodecCtx->width;
	//play_stream.screen_h = pCodecCtx->height;
	//
	//if (!hWnd)
	//{
	//	play_stream.screen = SDL_CreateWindow("Simplest ffmpeg player's Window", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
	//		play_stream.screen_w, play_stream.screen_h,
	//		SDL_WINDOW_OPENGL);
	//}
	//else
	//{
	//	play_stream.screen = SDL_CreateWindowFrom(hWnd);

	//}
	//if (!play_stream.screen) {
	//	printf("SDL: could not create window - exiting:%s\n", SDL_GetError());
	//	return -1;
	//}

	//play_stream.sdlRenderer = SDL_CreateRenderer(play_stream.screen, -1, 0);
	////IYUV: Y + U + V  (3 planes)
	////YV12: Y + V + U  (3 planes)
	//play_stream.sdlTexture = SDL_CreateTexture(play_stream.sdlRenderer, SDL_PIXELFORMAT_IYUV, SDL_TEXTUREACCESS_STREAMING, pCodecCtx->width, pCodecCtx->height);

	//play_stream.sdlRect.x = 0;
	//play_stream.sdlRect.y = 0;
	//play_stream.sdlRect.w = play_stream.screen_w;
	//play_stream.sdlRect.h = play_stream.screen_h;

	////��ȡ��Ƶ֡  ��ʾ 
	//while (true)
	//{
	//	if (av_read_frame(play_stream.pFormatCtx, play_stream.packet) >= 0)
	//	{
	//		if (play_stream.packet->stream_index == play_stream.nVideoIndex)
	//		{
	//			ret = avcodec_decode_video2(pCodecCtx, play_stream.pFrameYUV, &play_stream.got_picture, play_stream.packet);
	//			if (ret < 0)
	//			{
	//				PKLog.LogMessage(PK_LOGLEVEL_ERROR, "Decode Error.\n");
	//				return -1;
	//			}
	//			if (play_stream.got_picture)
	//			{
	//				//ת��ȥ����Ч����
	//				sws_scale(play_stream.img_convert_ctx, (const unsigned char* const*)play_stream.pFrame->data, play_stream.pFrame->linesize, 0, pCodecCtx->height,
	//					play_stream.pFrameYUV->data, play_stream.pFrameYUV->linesize);

	//				//SDL_UpdateTexture(sdlTexture, &sdlRect, pFrameYUV->data[0], pFrameYUV->linesize[0]);

	//				SDL_UpdateYUVTexture(play_stream.sdlTexture, NULL,
	//					play_stream.pFrameYUV->data[0], play_stream.pFrameYUV->linesize[0],
	//					play_stream.pFrameYUV->data[1], play_stream.pFrameYUV->linesize[1],
	//					play_stream.pFrameYUV->data[2], play_stream.pFrameYUV->linesize[2]);

	//				SDL_RenderClear(play_stream.sdlRenderer);
	//				SDL_RenderCopy(play_stream.sdlRenderer, play_stream.sdlTexture, NULL, NULL);
	//				SDL_RenderPresent(play_stream.sdlRenderer);
	//				SDL_Delay(20);
	//			}
	//		}
	//		av_free_packet(play_stream.packet);
	//	}
	//}
	//////���һ�����ž����map
	//playInfo info = {0};
	//info.ipchannel = (char*)szChannel;
	//info.playid = nPlayID;
	//info.token = token;
	//v_playInfos.push_back(info);
	//m_mapPlayid2Handle.insert(std::map<long, LPVOID>::value_type(nPlayID, Handle));
	return VIDEO_SUCCESS;
}

// �Ͽ�ʵʱ��������
long CDVRFunc::VideoStopPlayVideo(long nPlayID)
{
	//ֹͣ����  �ͷŴ򿪵�������ڴ� 
	vector<playInfo>::iterator iter ;
	for (iter = v_playInfos.begin(); iter != v_playInfos.end();)
	{
		if (iter->playid==nPlayID)
		{
			CG28181Server::Bye(iter->token);
			ReleasePackets(iter->ipchannel);
			v_playInfos.erase(iter);
			return VIDEO_SUCCESS;
		}
		else{
			iter++;
		}
	}
	return EC_PK_VIDEO_FUNCPARAMINVALID;

}

// ��ʵʱ���Ź�����ץ��ͼƬ
long CDVRFunc::VideoRealPlayCapturePicture(long nPlayID, char* pszFileName, long nFileNameSize, long* pnPictureFormat)
{
	/*CString strTemp;
    if((pszFileName == NULL) || (pnPictureFormat == NULL))
    {
		strTemp.LoadString(IDS_STRING105);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
    }

	strTemp.LoadString(IDS_STRING152);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), pszFileName, nPlayID);

    long lRet;
	CString strFileName = pszFileName; //debug   "D:\\H3CDownload\\";//

	if((pszFileName == NULL) || (pnPictureFormat == NULL))
	{
		strTemp.LoadString(IDS_STRING153);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	PPLAY_INFO pPlayInfo = NULL;
	bool bFound = GetPlayInfoByPlayID(nPlayID, pPlayInfo);
	if(!bFound)
	{
		strTemp.LoadString(IDS_STRING154);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPlayID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nPlayID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(pPlayInfo->nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING155);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	//��ȡ·�����ļ���
	char szPicPath[256] = {0};
	char szPicName[256] = {0};
	for ( int i=nFileNameSize; i>0 ; i--)
	{
		if ( pszFileName[i] == '\\' || pszFileName[i] == '/' )
		{
			memcpy(szPicPath, pszFileName, i);
			memcpy(szPicName, pszFileName + i + 1, (nFileNameSize - i -1) );
			break;
		}
	}

	lRet = IMOS_SnatchOnce(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
		pPlayInfo->szXpCode,
		strFileName.GetBuffer(0),
		XP_PICTURE_JPG);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING156);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING157);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	*pnPictureFormat = XP_PICTURE_JPG;// XP_PICTURE_BMP;
	
	CString FilePath = szPicPath;
	FilePath += "/";
	CString FileName = szPicName;
	CString TempName;
	CString TempFileTitle;
	CFile Files;
    CFileFind Finder;
	int IsExist;
	
	//Ŀ¼���Ѿ�����Ҫץȡ��ͼƬ���ƣ���ɾ��
	IsExist = Finder.FindFile( FilePath + FileName + ".jpg" ); 
	while( IsExist )
	{
		IsExist = Finder.FindNextFile();
		TempFileTitle = Finder.GetFilePath();
		Files.Remove(TempFileTitle);
	}
	
	int nPos = 0;
	IsExist = Finder.FindFile( FilePath + "*.jpg" ); 	
	while( IsExist )
	{
		IsExist = Finder.FindNextFile();
		TempName = Finder.GetFileName();
		nPos = TempName.Find("201",0);
		//if( TempName.GetAt(0) == '-' )
		{
			TempFileTitle = Finder.GetFilePath();//.GetFileURL();
			strTemp.LoadString(IDS_STRING158);
			PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0),TempFileTitle,FilePath,FileName);
			Files.Rename( TempFileTitle, FilePath + FileName + ".jpg" );
			
			break;
		}
	}

	strTemp.LoadString(IDS_STRING159);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayID);
	*/
	return VIDEO_SUCCESS;
}

// ��ȡ��������(���ȣ��Աȶȣ����Ͷȣ�ɫ��)
long CDVRFunc::VideoGetVideoEffect(long nPlayID, long* pnBrightValue, long* pnContrastValue, long* pnSaturationValue, long* pnHueValue)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
    return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

// ������������(���ȣ��Աȶȣ����Ͷȣ�ɫ��)
long CDVRFunc::VideoSetVideoEffect(long nPlayID, long nBrightValue, long nContrastValue, long nSaturationValue, long nHueValue)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
	return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

// �����豸��ʱ��
long CDVRFunc::VideoSetDeviceTime(long nLoginID, time_t tmDevice)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
	return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

// ����ָ��ͨ��ָ��ʱ��ε�����Զ���ļ���Ϣ
long CDVRFunc::VideoFindRemoteFile(long nLoginID, char* szChannel, time_t tmStart, time_t tmEnd, CHisFileList* plistFileInfo)
{
	//if (!szChannel)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayVideo ͨ����Ϊ��");
	//	return EC_PK_VIDEO_NO_CHANNEL;
	//}
	//CString strTemp;
	//if ((plistFileInfo == NULL) || (tmStart < 0) || (tmEnd < 0)||
	//	(szChannel == NULL) || (szChannel[0] == '\0') || (tmEnd < tmStart))
	//{
	//	strTemp.LoadString(IDS_STRING160);
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
 //       CString strTip;
 //       strTip.Format(strTemp.GetBuffer(0));
 //       m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
	//	return EC_PK_VIDEO_FUNCPARAMINVALID;
	//}
	//strTemp.LoadString(IDS_STRING161);
 //   PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nLoginID);
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "Channel:%s", szChannel);

	////Start To Find Remote Files of vedio;
	//NETDEV_FILECOND_S stFileCond = { 0 };
	//stFileCond.dwChannelID = ::atoi(szChannel);
	//stFileCond.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL;
	//stFileCond.tBeginTime = tmStart;
	//stFileCond.tEndTime = tmEnd;
	// LPVOID dwFileHandle = NETDEV_FindFile((LPVOID)nLoginID, &stFileCond);
	// int nCount = 0;
	// int nReturnValue = VIDEO_SUCCESS;
	//if (NULL == dwFileHandle)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "NETDEV_FindFile Fail,ErrorCode:%d", iError);
	//	return EC_PK_VIDEO_FAILTOFINDVIDEOFILE;
	//}
	//else
	//{
	//	NETDEV_FINDDATA_S stVodFile = { 0 };
	//	while (NETDEV_FindNextFile(dwFileHandle, &stVodFile))
	//	{
	//		// д���ļ���Ϣ
	//		nCount++;
	//		CHisFile theFile;
	//		theFile.SetName(stVodFile.szFileName);
	//		theFile.SetStartTime(stVodFile.tBeginTime);
	//		theFile.SetEndTime(stVodFile.tEndTime);
	//		strcpy(theFile.m_szChannel, szChannel);
	//		memcpy(theFile.m_pRawHisFileStruct, &stVodFile, sizeof(NETDEV_FINDDATA_S)); // ������4K��С,���������Ա�ط�ʱ����ֱ��ʹ�ö�����ת��תȥ
	//		plistFileInfo->InsertObject(theFile);
	//		memset(&stVodFile, 0x00, sizeof(NETDEV_FINDDATA_S));
	//	}
	//	if (nCount == 0)
	//	{
	//		INT32 iError = NETDEV_GetLastError();
	//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "NETDEV_FindNextFile Fail,ErrorCode:%d", iError);
	//		if (41 == iError)  //@version ��ͬ�汾�ķ���ֵ�����в���   ��ǰʹ�õİ汾�������޸�������Ƶ������Ƶû������,������һ���汾
	//			nReturnValue = EC_PK_VIDEO_NO_PLAYBACK_RECODE;   //û�в�ѯ���ͷ���
	//	}
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "NETDEV_FindNextFile End.,nCount:%d", nCount);
	//if (TRUE != NETDEV_FindClose(dwFileHandle))	// Close Find Handle
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "NETDEV_FindClose Fail,ErrorCode:%d", iError);
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "NETDEV_FindClose Success.,nCount:%d", nCount);
	return 0;
}

// ���ļ����ط���ʷ¼��
long CDVRFunc::VideoPlayBackbyFileName(long nLoginID, CHisFile *pHisFile, HWND hWnd, long &nPlayID)
{
	//CString strTemp;
	//if ((pHisFile == NULL) || (hWnd == NULL))
	//{
	//	strTemp.LoadString(IDS_STRING167);
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
 //       CString strTip;
 //       strTip.Format(strTemp.GetBuffer(0));
 //       m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
 //       return EC_PK_VIDEO_FUNCPARAMINVALID;
	//}

	//strTemp.LoadString(IDS_STRING168);
 //   PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), pHisFile->m_szName, nLoginID);
	//
	//NETDEV_PLAYBACKCOND_S stPlayBackByTimeInfo = { 0 };
	//stPlayBackByTimeInfo.dwChannelID = ::atoi(pHisFile->m_szChannel);
	//stPlayBackByTimeInfo.tBeginTime = pHisFile->m_nStartTime;
	//stPlayBackByTimeInfo.tEndTime = pHisFile->m_nEndTime;
	//stPlayBackByTimeInfo.hPlayWnd = hWnd;
	//stPlayBackByTimeInfo.dwLinkMode = NETDEV_TRANSPROTOCAL_RTPTCP;
	//stPlayBackByTimeInfo.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL;
	//stPlayBackByTimeInfo.dwStreamMode = NETDEV_STREAM_MODE_VIDEO;
	////stPlayBackByTimeInfo.dwStreamIndex = NETDEV_LIVE_STREAM_INDEX_MAIN;
	////stPlayBackByTimeInfo.dwTransType = NETDEV_TRANS_TYPE_STRAIGHT;
	////stPlayBackByTimeInfo.dwPlaySpeed = NETDEV_PLAY_STATUS_1_FORWARD;
	//stPlayBackByTimeInfo.dwDownloadSpeed = NETDEV_DOWNLOAD_SPEED_ONE;
	//LPVOID lpHandle = NETDEV_PlayBackByTime(GetLoginHandle(nLoginID), &stPlayBackByTimeInfo);

	////NETDEV_PLAYBACKINFO_S stPlayBackByNameInfo = { 0 };
	////memcpy(stPlayBackByNameInfo.szName, pHisFile->m_szName, VIDEO_NAME_MAXSIZE);
	////stPlayBackByNameInfo.tBeginTime = pHisFile->m_nStartTime;
	////stPlayBackByNameInfo.tEndTime = pHisFile->m_nEndTime;
	////stPlayBackByNameInfo.hPlayWnd = hWnd;
	////stPlayBackByNameInfo.dwLinkMode = NETDEV_TRANSPROTOCAL_RTPTCP;
	////stPlayBackByNameInfo.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL; 
	////stPlayBackByNameInfo.dwDownloadSpeed = NETDEV_DOWNLOAD_SPEED_ONE;
	////LPVOID lpHandle = NETDEV_PlayBackByName(GetLoginHandle(nLoginID), &stPlayBackByNameInfo);
	//if (lpHandle == NULL)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "NETDEV_PlayBackByName Fail,ErrorCode:%d", iError);
	//	return EC_PK_VIDEO_FAILTOPLAYBACK;
	//}

	////���ļ�������  Ҳ������
	//BOOL res = NETDEV_OpenSound(lpHandle);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV NETDEV_PlayBackByName OpenSound fail,ErrorCode:%d", NETDEV_GetLastError());
	//}
	//nPlayID = reinterpret_cast<long>(lpHandle);
	//vector<time_t> vec_time_list;
	//vec_time_list.push_back(pHisFile->m_nStartTime);
	//vec_time_list.push_back(pHisFile->m_nEndTime);
	//m_mapPlaybackId2TotalTime.insert(std::map<long, vector<time_t>>::value_type(nPlayID, vec_time_list));
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "NETDEV_PlayBackByName Success,PlayHandle:%d", nPlayID);
	return VIDEO_SUCCESS;
}

// ��ʱ��ط���ʷ¼��
long CDVRFunc::VideoPlayBackbyTime(long nLoginID, char* szChannel, time_t tmStart, time_t tmEnd, HWND hWnd, long &nPlayID)
{	
	//if (!szChannel)  
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayBackbyTime ͨ����Ϊ��");
	//	return EC_PK_VIDEO_NO_CHANNEL;
	//}
	//map<long, LPVOID>::iterator itLogin = m_mapLoginid2Handle.find(nLoginID);
	//if (itLogin == m_mapLoginid2Handle.end())  //��ʾû�в��ҵ���¼���
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayBackbyTime Loginid invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}	
	//CString strTemp;
	//if ((tmStart >= tmEnd) || (hWnd == NULL) || (tmEnd <= 0 || tmStart <= 0) || !szChannel)
	//{
	//	//strTemp.LoadString(IDS_STRING167);
	//	//PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
	//	//CString strTip;
	//	//strTip.Format(strTemp.GetBuffer(0));
	//	//m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayBackbyTime invaild Param");
	//	return EC_PK_VIDEO_FUNCPARAMINVALID;
	//}
	////��ӡ�طŵĿ�ʼʱ��ͽ���ʱ��
	//ACE_Date_Time tvsDate = ACE_Date_Time(ACE_Time_Value(tmStart));
	//ACE_Date_Time tveDate = ACE_Date_Time(ACE_Time_Value(tmEnd));
	//char szSTime[128] = {0};
	//char szETime[128] = { 0 };
	//sprintf(szSTime, "%04d-%02d-%02d %02d:%02d:%02d", tvsDate.year(), tvsDate.month(), tvsDate.day(), tvsDate.hour(), tvsDate.minute(), tvsDate.second());
	//sprintf(szETime, "%04d-%02d-%02d %02d:%02d:%02d", tveDate.year(), tveDate.month(), tveDate.day(), tveDate.hour(), tveDate.minute(), tveDate.second());
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV  Param start time :%s,end time :%s", szSTime, szETime);

	////@time 2019-05-16 chengguo ������Ƶ����
	////�������ӵĹٷ��ĵ��ĵ������̣����ð�ʱ��طŵ���ʷ��Ƶ��
	////�����Ȳ����ļ��б�Ȼ���ڰ�ʱ�䲥����ʷ��Ƶ�����򲥷���Ƶʧ��
	////Start To Find Remote Files of vedio;
	//NETDEV_FILECOND_S stFileCond = { 0 };
	//stFileCond.dwChannelID = ::atoi(szChannel);  //@version-1��jiachao szChannel+1��@version-2 chengguo szChannel
	//stFileCond.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL;
	//stFileCond.dwStreamType = NETDEV_LIVE_STREAM_INDEX_MAIN;
	//stFileCond.tBeginTime = tmStart;
	//stFileCond.tEndTime = tmEnd;
	//LPVOID dwFileHandle = NETDEV_FindFile((LPVOID)nLoginID, &stFileCond);
	//int nCount = 0;
	//int nReturnValue = VIDEO_SUCCESS;
	//if (NULL == dwFileHandle)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV FindRemoteFile Fail,szChannel:%s,ErrorCode:%d", szChannel, NETDEV_GetLastError());
	//	return EC_PK_VIDEO_FAILTOFINDVIDEOFILE;
	//}
	//vector<NETDEV_FINDDATA_S> vecVodFile; //��Ų���¼����ļ���¼��Ĵ洢�ǰ����ļ�����
	//vecVodFile.clear();
	//NETDEV_FINDDATA_S stVodFile = { 0 };
	//while (NETDEV_FindNextFile(dwFileHandle, &stVodFile))
	//{
	//	// д���ļ���Ϣ
	//	nCount++;
	//	//@time 2019-05-23 chengguo ��ѯ���¼���ļ�ʱ,������Ҫƴ�Ӳ��� ,00-06:30   06:30---12:00
	//	vecVodFile.push_back(stVodFile);    
	//	memset(&stVodFile, 0x00, sizeof(NETDEV_FINDDATA_S));
	//}
	//if (nCount == 0)
	//{   
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV NETDEV_FindNextFile Fail,ErrorCode:%d", iError);
	//	if (41 == iError)
	//		nReturnValue = EC_PK_VIDEO_NO_PLAYBACK_RECODE; //��ʾ�������óɹ���������¼�� 13000
	//	else
	//		nReturnValue = EC_PK_VIDEO_FAILTOFINDVIDEOFILE;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV NETDEV_FindNextFile End.,nCount:%d", nCount);
	////Close Find Handle
	//if (TRUE != NETDEV_FindClose(dwFileHandle))
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV NETDEV_FindClose Fail,ErrorCode:%d", NETDEV_GetLastError());
	//}
	////δ��ѯ��¼�� ��֮�䷵����
	//if (EC_PK_VIDEO_NO_PLAYBACK_RECODE == nReturnValue)
	//	return nReturnValue;

	////�ж��²�ѯ�ļ���ʱ���Ƿ������ѯ�Ŀ�ʼʱ��ͽ���ʱ��
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV file start time :%lld,end time :%lld��Param start time:%lld,end time:%lld", vecVodFile[0].tBeginTime, vecVodFile[0].tEndTime, tmStart, tmEnd);
	//if (vecVodFile[0].tBeginTime > tmStart)   //����ʱ���� ��ʱ����Ϊ�ļ��б�ʱ��
	//{
	//	tmStart = vecVodFile[0].tBeginTime;  
	//}
	//if (vecVodFile[0].tEndTime < tmEnd)
	//{
	//	tmEnd = vecVodFile[0].tEndTime;
	//}

	//NETDEV_PLAYBACKCOND_S stPlayBackByTimeInfo = { 0 };
	//stPlayBackByTimeInfo.dwChannelID = ::atoi(szChannel);  
	//stPlayBackByTimeInfo.tBeginTime = tmStart;
	//stPlayBackByTimeInfo.tEndTime = tmEnd;
	//stPlayBackByTimeInfo.hPlayWnd = hWnd;
	//stPlayBackByTimeInfo.dwLinkMode = NETDEV_TRANSPROTOCAL_RTPTCP;
	//stPlayBackByTimeInfo.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL;
	//stPlayBackByTimeInfo.dwStreamMode = NETDEV_STREAM_MODE_ALL;
	////stPlayBackByTimeInfo.dwStreamIndex = NETDEV_LIVE_STREAM_INDEX_MAIN;
	////stPlayBackByTimeInfo.dwTransType = NETDEV_TRANS_TYPE_STRAIGHT;
	////stPlayBackByTimeInfo.dwPlaySpeed = NETDEV_PLAY_STATUS_1_FORWARD;
	//stPlayBackByTimeInfo.dwDownloadSpeed = NETDEV_DOWNLOAD_SPEED_ONE;

	//LPVOID lpLoginHandle = GetLoginHandle(nLoginID);
	//LPVOID lpHandle = NETDEV_PlayBackByTime(lpLoginHandle, &stPlayBackByTimeInfo);
	//if (lpHandle == NULL)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackByTime Fail,ErrorCode:%d", iError);
	//	return EC_PK_VIDEO_FAILTOPLAYBACK;
	//}
	//BOOL res = NETDEV_OpenSound(lpHandle);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackByTime OpenSound fail,ErrorCode:%d", NETDEV_GetLastError());
	//}

	//nPlayID = reinterpret_cast<long>(lpHandle);
	//vector<time_t> vec_time_list;
	//vec_time_list.push_back(tmStart);
	//vec_time_list.push_back(tmEnd);
	////ʵʱ��ȡ�طŵĽ��ȵ�ʱ��,��Ҫ��ֵ
	//m_mapPlaybackId2TotalTime.insert(std::map<long, vector<time_t>>::value_type(nPlayID, vec_time_list));  
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "NETDEV_PlayBackByName Success,PlayHandle:%d", nPlayID);
	return VIDEO_SUCCESS;
}

// ֹͣ�ط���ʷ¼��
long CDVRFunc::VideoStopPlayBack(long nPlayBackID)
{
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoStopPlayBack nPlayBackID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//LPVOID pPlayBack = (LPVOID)nPlayBackID;
	//BOOL res = NETDEV_CloseSound(pPlayBack);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV StopPlayBack CloseSound fail,ErrorCode:%d", NETDEV_GetLastError());
	//}
	//res = NETDEV_StopPlayBack(pPlayBack);
	//if (!res)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoStopPlayBack fail,Error Code:%d", iError);
	//	return EC_PK_VIDEO_FAILTOSTOPPLAYBACK;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "DVRUNV VideoStopPlayBack success");
	//m_mapPlaybackId2TotalTime.erase(iter);  //���һ��map
	return 0;
}

// ��ͣ�ط���ʷ¼��
long CDVRFunc::VideoPausePlayBack(long nPlayBackID)
{
	/*std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	if (iter == m_mapPlaybackId2TotalTime.end())
	{
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPausePlayBack nPlayBackID invaild");
		return EC_PK_VIDEO_MONITORNOTEXIST;
	}
	LPVOID pPlayBack = (LPVOID)nPlayBackID;
	BOOL res = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_PAUSE, NULL);
	if (!res)
	{
		INT32 iError = NETDEV_GetLastError();
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackControlPause fail,Error Code:%d", iError);
		return EC_PK_VIDEO_FAILTOPAUSEPLAYBACK;
	}
	PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "DVRUNV PlayBackControlPause success");*/
	return VIDEO_SUCCESS;
}

// �����ط���ʷ¼��
long CDVRFunc::VideoContinuePlayBack(long nPlayBackID)
{
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoContinuePlayBack nPlayBackID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//LPVOID pPlayBack = (LPVOID)nPlayBackID;
	//BOOL res = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_RESUME, NULL);
	//if (!res)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackControlRESUME  fail,Error code:%d", iError);
	//	return iError;
	//}
	////@version2019-06-13  chengguo 
	////�޸��˼����طŵĽӿ�,�����Ż������ź���ͣ��  ����һ�ε��ٶ�������Ϊ�����ٶ�
	//int enSpeed = 9;
	// res = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_SETPLAYSPEED, &enSpeed);
	//if (!res)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackControlRESUME set normal speed fail,Error Code :%d", iError);
	//	return EC_PK_VIDEO_FAILTOCONTINUEPLAYBACK;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "VideoContinuePlayBack success");
	//BOOL res = NETDEV_OpenSound(pPlayBack);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV PlayBackByTime OpenSound fail,ErrorCode:%d", NETDEV_GetLastError());
	//}
	return VIDEO_SUCCESS;
}

// �ӿ�ط���ʷ¼��
long CDVRFunc::VideoPlayFast(long nPlayBackID)
{
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayFast nPlayBackID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//LPVOID pPlayBack = (LPVOID)nPlayBackID;
	//INT32 enSpeed = 0;
	////�Ȼ�ȡ��ǰ�Ĳ����ٶ�
	//BOOL bRet = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_GETPLAYSPEED, &enSpeed);
	//if (TRUE != bRet)
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayFast Get Speed fail,Error Code :%d", NETDEV_GetLastError());
	//else
	//	PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoPlayFast Get Speed Success,speed:%d", enSpeed);
	////@time 2019-05-23 chengguo ֻ�п��������,����ı���Ϊ2,4,8,16 ���ŵ��ٶ�Ϊ1/2 1/4 ��������  
	////fast speed 10,11,12,13     slow 7,8   ����Ϊ9
	//if (enSpeed < 9)
	//	enSpeed = 10;
	//enSpeed = enSpeed + 1 <= NETDEV_PLAY_STATUS_16_FORWARD_IFRAME ? (enSpeed + 1) : enSpeed;   
	///*while ((enSpeed <= NETDEV_PLAY_STATUS_16_FORWARD) && (enSpeed >= NETDEV_PLAY_STATUS_2_FORWARD))  
	//{
	//	enSpeed++;
	//}*/
	//BOOL res = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_SETPLAYSPEED, &enSpeed);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlayFast fail,Error Code :%d", NETDEV_GetLastError());
	//	return EC_PK_VIDEO_FAILTOPLAYFAST;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoPlayFast success");
	return VIDEO_SUCCESS;
}

// ���ط���ʷ¼��
long CDVRFunc::VideoPlaySlow(long nPlayBackID)
{
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlaySlow nPlayBackID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//LPVOID pPlayBack = (LPVOID)nPlayBackID;
	//INT32 enSpeed = 0;
	//BOOL bRet = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_GETPLAYSPEED, &enSpeed); 
	//if (TRUE != bRet)
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlaySlow Get Speed fail,Error Code :%d", NETDEV_GetLastError());
	//else
	//	PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoPlaySlow Get Speed Success,speed:%d", enSpeed);
	//if (enSpeed > 9)
	//	enSpeed = 9;
	////@time 2019-05-23 chengguo  �����˲��Ÿ���Ϊ����
	//enSpeed = enSpeed - 1 >= NETDEV_PLAY_STATUS_QUARTER_FORWARD ? (enSpeed - 1) : enSpeed;
	////while ((enSpeed <= NETDEV_PLAY_STATUS_HALF_FORWARD) && (enSpeed >= NETDEV_PLAY_STATUS_QUARTER_FORWARD))
	////{
	////	enSpeed--;
	////}
	//BOOL res = NETDEV_PlayBackControl(pPlayBack, NETDEV_PLAY_CTRL_SETPLAYSPEED, &enSpeed);
	//if (!res)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlaySlow fail,Error Code :%d", NETDEV_GetLastError());
	//	return EC_PK_VIDEO_FAILTOPLAYSLOW;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoPlaySlow success");
	return VIDEO_SUCCESS;
}
/**
*                             _ooOoo_
*                            o8888888o
*                            88" . "88   
*                            (| -_- |)  
*                            O\  =  /O 
*                         ____/`---'\____
*                       .'  \\|     |//  `.
*                      /  \\|||  :  |||//  \
*                     /  _||||| -:- |||||-  \
*                     |   | \\\  -  /// |   |
*                     | \_|  ''\---/''  |   |
*                     \  .-\__  `-`  ___/-. /
*                   ___`. .'  /--.--\  `. . __
*                ."" '<  `.___\_<|>_/___.'  >'"".
*               | | :  `- \`.;`\ _ /`;.`/ - ` : | |
*               \  \ `-.   \_ __\ /__ _/   .-` /  /
*          ======`-.____`-.___\_____/___.-`____.-'======
*                             `=---='
*          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
*                    @author guo.cheng
*/

//��ȡ���ڻطŵ���Ϣ
long CDVRFunc::VideoGetPlayBackInfo(long nPlayBackID, long &nTotalTime, long &nCurrTime, long &nPos)
{
//	std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
//	if (iter == m_mapPlaybackId2TotalTime.end())
//	{
//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoGetPlayBackInfo nPlayBackID invaild");
//		return EC_PK_VIDEO_MONITORNOTEXIST;
//	}
//	INT64 iPlayTime = 0;
//	LPVOID pPlayBcakHandle = (LPVOID)nPlayBackID;
//	BOOL bRet = NETDEV_PlayBackControl(pPlayBcakHandle, NETDEV_PLAY_CTRL_GETPLAYTIME, &iPlayTime);
//	if (TRUE != bRet)
//	{
//		INT32 iError = NETDEV_GetLastError();
//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV GetPlaybackPos Fail,nPlayBackID:%d,ErrorCode:%d", nPlayBackID, iError);
//		return EC_PK_VIDEO_FAILTOGETPLAYBACKINFO;
//	}
//	nCurrTime = iPlayTime;  //��ȡ���Ž���
//#if 0
//	auto fun = [&, this](std::map<long, vector<time_t>> ::reference map_data)->void{
//		if (map_data.first == nPlayBackID){
//			vector<time_t> &vec = map_data.second;  //0--starttime 1---endtime
//			long startime = vec[1] > vec[0] ? vec[0] : vec[1];
//			nTotalTime = labs(vec[1] - vec[0]);
//			long currentPos = labs(iPlayTime - startime);
//			//nCurrTime = nCurrTime - vec[0];
//			nPos = currentPos;  //�طŵ�λ��
//			//@version 2019-06-11 chengguo  Ϊ�˼��ݲ�Ʒ��js �Ƚ�nPos ��ֵ������0��100֮��
//			nPos = (1.0*currentPos / nTotalTime *100 );   //
//		}};
//	std::for_each(m_mapPlaybackId2TotalTime.begin(), m_mapPlaybackId2TotalTime.end(), fun);
//#endif
//	vector<time_t> vec = iter->second;
//	long startime = vec[1] > vec[0] ? vec[0] : vec[1];  //��ʼ��ʱ���
//	nTotalTime = labs(vec[1] - vec[0]);  //��ʱ��
//	long currentPos = labs(iPlayTime - startime);
//	if (currentPos == nTotalTime)
//		nPos = 100;
//	else
//		nPos = (1.0*currentPos / nTotalTime * 100);
//	PKLog.LogMessage(PK_LOGLEVEL_DEBUG, "DVRUNV VideoGetPlayBackInfo Current Pos  %d",nPos);
	//@version 2019-06-17 chengguo ������ϲ�Ӧ��ֹͣ���ţ���Ϊ�п��ܻ�����ק������
	//if (100 == nPos)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV GetPlaybackPos  100% ,StopPalyBack Success");
	//	VideoStopPlayBack(nPlayBackID);
	//}
	//�����ļ��ط�ʱ����ŵ������ʱ�䣬��������ļ�ͷ�Ĳ���ʱ�䣬��λΪ��;
	//�㲥�ط�ʱ����ŵ��Ǿ���ʱ�䣬��λΪ��;
	/*
	long CurPos;
	lRet = IMOS_GetPlayedTimeEx(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->pstPlayWndInfoList[pPlayInfo->nIMosPlayID].szPlayWndCode,(unsigned long *)&CurPos);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING236);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING237);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	nPos=CurPos;
	nTotalTime=0;

	//�ؼ��У��˴�Ϊ����ڿ�ʼʱ��ʱ�����ֵ�����ڱ�����
	//1�������ļ��ط�ʱ����ŵ������ʱ�䣬��������ļ�ͷ�Ĳ���ʱ�䣬��λΪ�롣
	//2���㲥�ط�ʱ����ŵ��Ǿ���ʱ�䣬��λΪ�롣
	nCurrTime = CurPos - (long)(pPlayInfo->tmStart);
	if(nCurrTime < 0)
		nCurrTime = 0;
	*/
	return VIDEO_SUCCESS;
}

//���ûط�λ��
long CDVRFunc::VideoSetPlayBackPos(long nPlayBackID, long nPos)
{
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nPlayBackID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoSetPlayBackPos nPlayBackID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//CString strTemp;
	//if ((nPlayBackID < 0) || (nPos < 0))
	//{
	//	strTemp.LoadString(IDS_STRING239);
 //       PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
 //       m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
 //       return EC_PK_VIDEO_FUNCPARAMINVALID;
	//}
	//strTemp.LoadString(IDS_STRING240);
 //   PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayBackID, nPos);
	////@time 2019-05-24 ����,���õ�λ����Ϣ Ӧ��Ҫ���Ͽ�ʼ�Ļطŵ�ʱ��,���ò��ŵ�ʱ��
	//vector<time_t> vecTime = iter->second;  // //0--starttime 1---endtime

	//nPos = nPos > 100 ? 100 : nPos;  //��ܴ���

	////@2019-06-11 ����eview��js ,pos��ֵΪ0��100֮��
	//long nPosTime = nPos*labs(vecTime[1] - vecTime[0])/100;
	//long nSetPos = vecTime[0] + nPosTime;

	////long nSetPos = vecTime[0] + nPos;


	//LPVOID pPlayBackHandle = (LPVOID)nPlayBackID;
	////���ûطŵ�λ��
	//BOOL bRet = NETDEV_PlayBackControl(pPlayBackHandle, NETDEV_PLAY_CTRL_SETPLAYTIME, &nSetPos);
	//if (TRUE != bRet)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV Set Playback Pos Fail,ErrorCode:%d", iError);
	//	return EC_PK_VIDEO_FAILTOSETPLAYBACKPOS;  //���ش�����
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV Set Playback Pos %d Success", nPos);
	return VIDEO_SUCCESS;
}

// �ڻط���ʷ¼��ʱץ��ͼƬ
long CDVRFunc::VideoPlayBackCapturePicture(long nPlayBackID, char* pszFileName, long nFileNameSize,
										long* pnPictureFormat)
{
	/*CString strTemp;
    if ((pszFileName == NULL) || (pnPictureFormat == NULL))
    {
		strTemp.LoadString(IDS_STRING246);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
    }

	//��ͼƬ�ĺ�׺��ȥ��
	CString strPath = pszFileName;
	int nIndex = strPath.ReverseFind('.');
	strPath = strPath.Left(nIndex);

	//����ͬʵʱ����ץ��
	return VideoRealPlayCapturePicture(nPlayBackID, strPath.GetBuffer(0), nFileNameSize, pnPictureFormat);*/
	return 0;
}

// �ڻط���ʷ¼��ʱ����¼��
long CDVRFunc::VideoPlayBackSaveVideo(long nPlayBackID, char* pszFileName, long nFileNameSize, char* pszExtName, long nExtSize)
{
	/*CString strTemp;
	if ((nPlayBackID < 0) || (nFileNameSize < 0) || (NULL == pszFileName))
	{
		strTemp.LoadString(IDS_STRING247);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}
	strTemp.LoadString(IDS_STRING248);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayBackID);

	PPLAY_INFO pPlayInfo = NULL;
	bool bFound = GetPlayInfoByPlayID(nPlayBackID, pPlayInfo);
	if(!bFound)
	{
		strTemp.LoadString(IDS_STRING249);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPlayBackID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nPlayBackID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(pPlayInfo->nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING250);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	long lRet;

	lRet = IMOS_StartRecord(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->pstPlayWndInfoList[pPlayInfo->nIMosPlayID].szPlayWndCode, pszFileName, XP_MEDIA_FILE_FLV);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING251);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING252);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	strTemp.LoadString(IDS_STRING253);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayBackID);
	*/
	return VIDEO_SUCCESS;
}

// �ڻط���ʷ¼��ʱֹͣ����¼��
long CDVRFunc::VideoStopPlayBackSaveVideo(long nPlayBackID)
{
	/*CString strTemp;
	if (nPlayBackID < 0)
	{
		strTemp.LoadString(IDS_STRING254);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}
	strTemp.LoadString(IDS_STRING255);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayBackID);

	PPLAY_INFO pPlayInfo = NULL;
	bool bFound = GetPlayInfoByPlayID(nPlayBackID, pPlayInfo);
	if(!bFound)
	{
		strTemp.LoadString(IDS_STRING256);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPlayBackID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nPlayBackID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(pPlayInfo->nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING257);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	long lRet = IMOS_StopRecord(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->pstPlayWndInfoList[pPlayInfo->nIMosPlayID].szPlayWndCode);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING258);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING259);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	strTemp.LoadString(IDS_STRING260);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), nPlayBackID);
	*/
	return VIDEO_SUCCESS;
}
 
// ���ļ�������ʷ¼��
long CDVRFunc::VideoDownloadbyFileName(long nLoginID, char* szChannel, char* pszRemoteFileName, long nRemoteFileNameSize, 
									   char* pszLocalFileName, long nLocalFileNameSize, long &nDownLoadID)
{
	/*CString strTemp;
	if ((nLoginID < 0) || (pszRemoteFileName == NULL) || (nRemoteFileNameSize < 0) ||
		(pszLocalFileName == NULL) || (nLocalFileNameSize < 0))
	{
		strTemp.LoadString(IDS_STRING261);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}
	strTemp.LoadString(IDS_STRING262);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), pszRemoteFileName, nLoginID);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING263);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	if ((szChannel == NULL) || (szChannel[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING141);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	long lRet;
    GET_URL_INFO_S stGetUrlInfo = {0};
    URL_INFO_S stUrlInfo = {0};
	
    strncpy(stGetUrlInfo.szFileName, pszRemoteFileName, IMOS_FILE_NAME_LEN);
    strncpy(stGetUrlInfo.szClientIp, pDeviceInfo->stLoginInfo.stUserLoginIDInfo.szUserIpAddress, IMOS_IPADDR_LEN);
	strncpy(stGetUrlInfo.szCamCode, szChannel, IMOS_RES_CODE_LEN);
	//API_TimeToStringEX(stGetUrlInfo.stRecTimeSlice.szBeginTime,tmStart);
	//API_TimeToStringEX(stGetUrlInfo.stRecTimeSlice.szEndTime, tmEnd);

	// �˴�ʼ�շ���ʧ�ܣ�������12312���豸�����ڡ���Ӧ����stGetUrlInfo.szCamCode��Ҫ���ã����ǰ�������Ŀǰ�Ľӿ���ƣ���λ�õ����ļ���Ӧ��CamCode��������
	lRet = 	IMOS_GetRecordFileURL(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,&stGetUrlInfo,&stUrlInfo);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING264);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING265);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}

	/* ������ý������pszLocalFileName ���غ󱣴浽���ص��ļ�·�����������ļ�������·�����治��б�ܣ� 
	DOWNLOAD_INFO downloadInfo;
	downloadInfo.nLoginID = nLoginID;
	strncpy(downloadInfo.szStartTime, stGetUrlInfo.stRecTimeSlice.szBeginTime, sizeof(downloadInfo.szStartTime));
	strncpy(downloadInfo.szEndTime, stGetUrlInfo.stRecTimeSlice.szEndTime, sizeof(downloadInfo.szEndTime));

	lRet = IMOS_OpenDownloadEx(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
		stUrlInfo.szURL,
		stUrlInfo.stVodSeverIP.szServerIp,
		stUrlInfo.stVodSeverIP.usServerPort,
		XP_PROTOCOL_TCP,
		//XP_DOWN_MEDIA_SPEED_ONE,
		//pszLocalFileName,
		//XP_MEDIA_FILE_FLV,
		downloadInfo.szDownload);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING266);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING267);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}

	/* ���� DecoderTag added by ���� 20150119 
	lRet = IMOS_SetDecoderTag(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
		downloadInfo.szDownload,
		stUrlInfo.szDecoderTag);
	if(ERR_COMMON_SUCCEED != lRet) {
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "set decoder tag error: %d", lRet);
		m_pSetSDKErrInfoCallback(false, lRet, "set decoder tag error", 0, "");
		return lRet;
	}
	
	/* ��ʼ����ý���� 
	lRet = IMOS_StartDownloadEx(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, downloadInfo.szDownload, pszLocalFileName, XP_MEDIA_FILE_TS, XP_DOWN_MEDIA_SPEED_ONE, NULL);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING268);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING269);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}

	m_nDownloadIndex++;
	nDownLoadID = m_nDownloadIndex;
	m_mapDownload.insert(DOWNLOADMAP::value_type(m_nDownloadIndex, downloadInfo));

	strTemp.LoadString(IDS_STRING270);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0), pszRemoteFileName, nLoginID);*/
	return VIDEO_SUCCESS;
}

// �����ع�����ֹͣ����
long CDVRFunc::VideoStopDownload(long nDownloadID)
{
	//PKLog.LogMessage(PK_LOGLEVEL_NOTICE, "DVRUNV StopDownloadPos  Start");
	//std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nDownloadID);
	//if (iter == m_mapPlaybackId2TotalTime.end())
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoStopDownload nDownloadID invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//LPVOID pDownLoad = (LPVOID)nDownloadID;
	//BOOL bres=NETDEV_StopGetFile(pDownLoad);
	//if (!bres)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoStopDownload Fail,ErrorCode:%d", NETDEV_GetLastError());
	//	return EC_PK_VIDEO_FAILTOSTOPDOWNLOADVIDEO;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV StopDownloadPos  Success and erase map");
	//m_mapPlaybackId2TotalTime.erase(iter);  //ֹͣ���ؾ����һ�����ض����Ӧ�Ĺ�ϵ
	return VIDEO_SUCCESS;
}

// ��ʱ��������ʷ¼��
long CDVRFunc::VideoDownloadbyTime(long nLoginID, char* szChannel, time_t tmStart, time_t tmEnd, 
								char* pszLocalFileName, long nLocalFileNameSize, long &nDownLoadID, char* pszExtName, long nExtSize)
{
	//if (!szChannel)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoDownloadbyTime ͨ����Ϊ��");
	//	return EC_PK_VIDEO_NO_CHANNEL;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV In VideoDownloadbyTime, Loginid:%d", nLoginID);
	//map<long, LPVOID>::iterator itLogin = m_mapLoginid2Handle.find(nLoginID);
	//if (itLogin == m_mapLoginid2Handle.end())  //��ʾû�в��ҵ���¼���
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoDownloadbyTime Loginid invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}
	//CString strTemp;
	//if ((tmStart > tmEnd)  || (tmEnd <= 0 || tmStart <= 0))
	//{
	//	strTemp.LoadString(IDS_STRING167);
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
	//	CString strTip;
	//	strTip.Format(strTemp.GetBuffer(0));
	//	m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoDownloadbyTime invaild Param");
	//	return EC_PK_VIDEO_FUNCPARAMINVALID;
	//}
	////��ӡ���صĿ�ʼʱ��ͽ���ʱ��
	//ACE_Date_Time tvsDate = ACE_Date_Time(ACE_Time_Value(tmStart));
	//ACE_Date_Time tveDate = ACE_Date_Time(ACE_Time_Value(tmEnd));
	//char szSTime[128] = { 0 };
	//char szETime[128] = { 0 };
	//sprintf(szSTime, "%04d-%02d-%02d %02d:%02d:%02d", tvsDate.year(), tvsDate.month(), tvsDate.day(), tvsDate.hour(), tvsDate.minute(), tvsDate.second());
	//sprintf(szETime, "%04d-%02d-%02d %02d:%02d:%02d", tveDate.year(), tveDate.month(), tveDate.day(), tveDate.hour(), tveDate.minute(), tveDate.second());
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV download start time :%s,end time :%s", szSTime, szETime);

	////@time 2019-05-16 chengguo ������Ƶ����
	////�������ӵĹٷ��ĵ��ĵ������̣����ð�ʱ�����ص���ʷ��Ƶ�������Ȳ����ļ��б�Ȼ���ڰ�ʱ�䲥����ʷ��Ƶ�����򲥷���Ƶʧ��
	////Start To Find Remote Files of vedio;

	////��һ����ѯ¼��
	//NETDEV_FILECOND_S stFileCond = { 0 };
	//stFileCond.dwChannelID = ::atoi(szChannel);  //@version-1��jiachao szChannel+1��@version-2 chengguo szChannel
	//stFileCond.dwFileType = NETDEV_TYPE_STORE_TYPE_ALL;
	//stFileCond.tBeginTime = tmStart;
	//stFileCond.tEndTime = tmEnd;
	//LPVOID dwFileHandle = NETDEV_FindFile((LPVOID)nLoginID, &stFileCond);
	//int nCount = 0;
	//int nReturnValue = VIDEO_SUCCESS;
	//if (NULL == dwFileHandle)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV Download FindRemoteFile Fail,ErrorCode:%d", NETDEV_GetLastError());
	//	return EC_PK_VIDEO_FAILTOFINDVIDEOFILE;
	//}

	//vector<NETDEV_FINDDATA_S> vecVodFile; //��Ų���¼����ļ���¼��Ĵ洢�ǰ����ļ�����
	//vecVodFile.clear();
	//NETDEV_FINDDATA_S stVodFile = { 0 };
	//while (NETDEV_FindNextFile(dwFileHandle, &stVodFile))
	//{
	//	// д���ļ���Ϣ
	//	nCount++;
	//	//@time 2019-05-23 chengguo ��ѯ���¼���ļ�ʱ,������Ҫƴ�Ӳ��� ,00-06:30   06:30---12:00
	//	vecVodFile.push_back(stVodFile);
	//	memset(&stVodFile, 0x00, sizeof(NETDEV_FINDDATA_S));
	//}
	//if (nCount == 0)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV Download NETDEV_FindNextFile Fail,szChannel:%s,ErrorCode:%d", szChannel, iError);
	//	if (iError == 41)
	//		nReturnValue = EC_PK_VIDEO_NO_PLAYBACK_RECODE;    //û�в�ѯ��¼��ͷ����� 
	//	else
	//		nReturnValue = EC_PK_VIDEO_FAILTOFINDVIDEOFILE;
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV Download  NETDEV_FindNextFile End.,nCount:%d", nCount);
	////Close Find Handle
	//if (TRUE != NETDEV_FindClose(dwFileHandle))
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV Download NETDEV_FindClose Fail,ErrorCode:%d", NETDEV_GetLastError());
	//	//return -1;  //�ر��ļ����ʧ�ܲ�Ӧ�÷���
	//}
	//if (EC_PK_VIDEO_NO_PLAYBACK_RECODE == nReturnValue)
	//	return nReturnValue;

	////�ж��²�ѯ�ļ���ʱ���Ƿ������ѯ�Ŀ�ʼʱ��ͽ���ʱ��
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV  Download file start time :%lld,end time :%lld��Param start time:%lld,end time:%lld", szSTime, szETime, tmStart, tmEnd);
	//if (vecVodFile[0].tBeginTime > tmStart)   //����ʱ���� ��ʱ����Ϊ�ļ��б�ʱ��
	//{
	//	tmStart = vecVodFile[0].tBeginTime;
	//}
	//if (vecVodFile[0].tEndTime < tmEnd)
	//{
	//	tmEnd = vecVodFile[0].tEndTime;
	//}

	//NETDEV_PLAYBACKCOND_S stPlayBackByTimeInfo = { 0 };
	//stPlayBackByTimeInfo.dwChannelID = ::atoi(szChannel);
	//stPlayBackByTimeInfo.tBeginTime = tmStart;
	//stPlayBackByTimeInfo.tEndTime = tmEnd;
	////stPlayBackByTimeInfo.dwStreamMode = NETDEV_STREAM_MODE_ALL;  //@version 2019-05-29 ������ƵԶ�̵��� ���ص���Ƶû������ 
	//stPlayBackByTimeInfo.hPlayWnd = NULL;
	//stPlayBackByTimeInfo.dwDownloadSpeed = NETDEV_DOWNLOAD_SPEED_EIGHT;

	//string strFilePath = string(pszLocalFileName);
	//if (strFilePath.empty())
	//{
	//	string strBinpath = string(PKComm::GetBinPath());
	//	strFilePath = strBinpath + PK_OS_DIR_SEPARATOR + string(szSTime);
	//}
	//LPVOID pHandle = NETDEV_GetFileByTime((LPVOID)nLoginID, &stPlayBackByTimeInfo, (char*)strFilePath.c_str(), NETDEV_MEDIA_FILE_TS);
	//if (NULL == pHandle)
	//{
	//	INT32 iError = NETDEV_GetLastError();
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV NETDEV_GetFileByTime Fail,Error Code %d", iError);
	//	return EC_PK_VIDEO_FAILTODOWNLOADVIDEO;  //����¼��ʧ��
	//}
	//nDownLoadID = (long)pHandle;  //����һ������id
	//vector<time_t> vec_time_list;
	//vec_time_list.push_back(tmStart);
	//vec_time_list.push_back(tmEnd);
	////ʵʱ��ȡ�ط�,���ؽ��ȵ�ʱ��,��Ҫ��ֵ
	//m_mapPlaybackId2TotalTime.insert(std::map<long, vector<time_t>>::value_type(nDownLoadID, vec_time_list));  //����ID
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV DownLoadByTime Success");
	return VIDEO_SUCCESS;
}

// ��ѯ��ʷ¼������ؽ���
long CDVRFunc::VideoQueryDownloadPosition(long nDownloadID, long &nPos)
{
//	PKLog.LogMessage(PK_LOGLEVEL_DEBUG, "DVRUNV QueryDownloadPos");
//	std::map<long, std::vector<time_t>>::iterator iter = m_mapPlaybackId2TotalTime.find(nDownloadID);
//	if (iter == m_mapPlaybackId2TotalTime.end())
//	{
//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV QueryDownloadPos nDownloadID invaild");
//		return EC_PK_VIDEO_MONITORNOTEXIST;
//	}
//	INT64 iPlayTime = 0;
//	LPVOID pDownLoad = (LPVOID)nDownloadID;
//	//@chengguo  ���ؽ���Ӧ�úͻطŵĽ���ʹ�õ���ͬһ������
//	BOOL bRet = NETDEV_PlayBackControl(pDownLoad, NETDEV_PLAY_CTRL_GETPLAYTIME, &iPlayTime);
//	if (TRUE != bRet)
//	{
//		INT32 iError = NETDEV_GetLastError();
//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV GetDownLoadPos Fail,ErrorCode:%d", iError);
//		return EC_PK_VIDEO_FAILTOGETDOWNLOADPOS;
//	}
//#if 0
//	auto fun = [&, this](std::map<long, vector<time_t>> ::reference map_data)->void{
//		if (map_data.first == nDownloadID){
//			vector<time_t> &vec = map_data.second;  //0--starttime 1---endtime
//			long startime = vec[1] > vec[0] ? vec[0] : vec[1];
//			INT64 nTotalTime = labs(vec[1] - vec[0]);
//			long currentPos = labs(iPlayTime - startime);
//			//nPos = currentPos;  //�طŵ�λ��
//			nPos = (1.0*currentPos / nTotalTime * 100);
//		}};
//	std::for_each(m_mapPlaybackId2TotalTime.begin(), m_mapPlaybackId2TotalTime.end(), fun);
//#endif
//	vector<time_t> vec = iter->second; 
//	long startime = vec[1] > vec[0] ? vec[0] : vec[1];  //��ʼ��ʱ���
//	INT64 nTotalTime = labs(vec[1] - vec[0]);  //��ʱ��
//	long currentPos = labs(iPlayTime - startime);
//	if (currentPos == nTotalTime)
//		nPos = 100;
//	else
//		nPos = (1.0*currentPos / nTotalTime * 100);
//	PKLog.LogMessage(PK_LOGLEVEL_DEBUG, "DVRUNV GetDownLoadPos Success,Current Pos %d", nPos);
//	if (100 == nPos)
//	{
//		PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV GetDownLoadPos  100% ,StopDownload Success");
//		VideoStopDownload(nDownloadID);
//	}
	return VIDEO_SUCCESS;
}


// ��̨����(�����������ң��ٶȣ�1-5)
long CDVRFunc::VideoPanControl(long nPlayID, long nControlCode, long nSpeed, long lElpaseTime)
{

	//map<long, LPVOID>::iterator iter = m_mapPlayid2Handle.find(nPlayID);
	//if (iter == m_mapPlayid2Handle.end())  //û�в��ҵ����ŵľ��
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPanControl Fail,nPlayID is invaild");
	//	return EC_PK_VIDEO_PLAYIDNOTEXIST;
	//}
	//INT32  dwPtzCmd = NETDEV_PTZ_ALLSTOP;  //ȫָͣ��
	//if (0 == nSpeed)
	//{
	//	dwPtzCmd = NETDEV_PTZ_ALLSTOP;
	//}
	//else
	//{
	//	nSpeed = nSpeed > 9 ? 9 : nSpeed;  //���ӽ��ٶȿ�����1��9֮��
	//	nSpeed = nSpeed < 1 ? 1 : nSpeed;
	//}
	//	switch (nControlCode)
	//	{
	//	case VIDEO_ORIENT_LEFT:
	//		dwPtzCmd = NETDEV_PTZ_PANLEFT;
	//		break;
	//	case VIDEO_ORIENT_UP:
	//		dwPtzCmd = NETDEV_PTZ_TILTUP;
	//		break;
	//	case VIDEO_ORIENT_RIGHT:
	//		dwPtzCmd = NETDEV_PTZ_PANRIGHT;
	//		break;
	//	case VIDEO_ORIENT_DOWN:
	//		dwPtzCmd = NETDEV_PTZ_TILTDOWN;
	//		break;
	//	case VIDEO_ORIENT_DOWN_LEFT:
	//		dwPtzCmd = NETDEV_PTZ_LEFTDOWN;
	//		break;
	//	case VIDEO_ORIENT_DOWN_RIGHT:
	//		dwPtzCmd = NETDEV_PTZ_RIGHTDOWN;
	//		break;
	//	case VIDEO_ORIENT_UP_LEFT:
	//		dwPtzCmd = NETDEV_PTZ_LEFTUP;
	//		break;
	//	case VIDEO_ORIENT_UP_RIGHT:
	//		dwPtzCmd = NETDEV_PTZ_RIGHTUP;
	//		break;
	//	default:
	//		break;
	//	}
	//	BOOL bRes = NETDEV_PTZControl(GetPlayHandle(nPlayID), dwPtzCmd, nSpeed);
	//	if (!bRes)
	//	{
	//		INT32 iError = NETDEV_GetLastError();
	//		PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPanControl Fail,Error Code %d,PtzCmd:0x%x", iError, dwPtzCmd);
	//		return iError;  //��̨����ʧ��
	//	}
	//	PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoPanControl Success,PtzCmd:0x%x", dwPtzCmd);
	return VIDEO_SUCCESS;
}

// ��ͷ����(������Զ��������)
long CDVRFunc::VideoLensControl(long nPlayID, long nControlCode, long nSpeed, long lElpaseTime)
{
	//map<long, LPVOID>::iterator iter = m_mapPlayid2Handle.find(nPlayID);
	//if (iter == m_mapPlayid2Handle.end())  //û�в��ҵ����ŵľ��
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPanControl Fail,nPlayID is invaild");
	//	return EC_PK_VIDEO_PLAYIDNOTEXIST;
	//}
	//INT32  dwPtzCmd = NETDEV_PTZ_ALLSTOP;  //ȫָͣ��
	//if (0 == nSpeed)
	//{
	//	dwPtzCmd = NETDEV_PTZ_ALLSTOP;
	//}
	//else
	//{
	//	nSpeed = nSpeed > 9 ? 9 : nSpeed;  //���ӽ��ٶȿ�����1��9֮��
	//	nSpeed = nSpeed < 1 ? 1 : nSpeed;
	//}

	//if(nSpeed != 0)
	//{
	//	switch (nControlCode)
	//	{
	//	case VIDEO_CTRL_LENS_ZOOMIN:
	//		dwPtzCmd = NETDEV_PTZ_ZOOMTELE;
	//		break;
	//	case VIDEO_CTRL_LENS_ZOOMOUT:
	//		dwPtzCmd = NETDEV_PTZ_ZOOMWIDE;
	//		break;
	//	case VIDEO_CTRL_FOCUS_FAR:
	//		dwPtzCmd = NETDEV_PTZ_FOCUSFAR;
	//		break;
	//	case VIDEO_CTRL_FOCUS_NEAR:
	//		dwPtzCmd = NETDEV_PTZ_FOCUSNEAR;
	//		break;
	//	default:
	//		break;
	//	}
	//}
	//else
	//{
	//	switch (nControlCode)
	//	{
	//	case VIDEO_CTRL_LENS_ZOOMIN:
	//		dwPtzCmd = NETDEV_PTZ_ZOOMTELE_STOP;
	//		break;
	//	case VIDEO_CTRL_LENS_ZOOMOUT:
	//		dwPtzCmd = NETDEV_PTZ_ZOOMWIDE_STOP;
	//		break;
	//	case VIDEO_CTRL_FOCUS_FAR:
	//		dwPtzCmd = NETDEV_PTZ_FOCUSFAR_STOP;
	//		break;
	//	case VIDEO_CTRL_FOCUS_NEAR:
	//		dwPtzCmd = NETDEV_PTZ_FOCUSNEAR_STOP;
	//		break;
	//	default:
	//		break;
	//	}
	//}
	//BOOL bRes = NETDEV_PTZControl(GetPlayHandle(nPlayID), dwPtzCmd, nSpeed);
	//if (!bRes)
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoLensControl Fail,Error Code %d,PtzCmd:0x%x", NETDEV_GetLastError(), dwPtzCmd);
	//	return EC_PK_VIDEO_FAILTOPANCONTROL;  //��̨����ʧ��
	//}
	//PKLog.LogMessage(PK_LOGLEVEL_INFO, "DVRUNV VideoLensControl Success,PtzCmd:0x%x", dwPtzCmd);
	

	return VIDEO_SUCCESS;
}

// Ԥ��λ����(���ã�����)
long CDVRFunc::VideoPresetPositionControl(long nLoginID, char* szChannel, long nControlCode, long nPresetIndex)
{
/*	CString strTemp;
	strTemp.LoadString(IDS_STRING307);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));

	if ((nControlCode < 0) || (nPresetIndex < 0))
	{
		strTemp.LoadString(IDS_STRING308);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING309);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	if ((szChannel == NULL) || (szChannel[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING141);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	long lRet;
	PRESET_INFO_S PresetInfo = {0};

	switch (nControlCode)
	{
	case VIDEO_CTRL_PSP_ADD:
		{
			PresetInfo.ulPresetValue=nPresetIndex;
			CString strTemp2;
			strTemp.LoadString(IDS_STRING310);
//			strTemp2.Format(strTemp.GetBuffer(0), nPresetIndex);
			strTemp2.Format("Preset_%d", nPresetIndex);
			strcpy(PresetInfo.szPresetDesc, strTemp2.GetBuffer(0));

			lRet = IMOS_SetPreset(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, szChannel, &PresetInfo);
			if (ERR_COMMON_SUCCEED != lRet)
			{
				strTemp.LoadString(IDS_STRING311);
				PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPresetIndex, lRet);
                CString strTip;
				strTemp.LoadString(IDS_STRING312);
                strTip.Format(strTemp.GetBuffer(0), nPresetIndex, lRet);
                m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
                return lRet;
			}
		}
		break;
	case VIDEO_CTRL_PSP_APPLY:
		{
			lRet = IMOS_UsePreset(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, szChannel, nPresetIndex);
			if (ERR_COMMON_SUCCEED != lRet)
			{
				strTemp.LoadString(IDS_STRING313);
				PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPresetIndex, lRet);
                CString strTip;
				strTemp.LoadString(IDS_STRING314);
                strTip.Format(strTemp.GetBuffer(0), nPresetIndex, lRet);
                m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
                return lRet;
			}
		}		
		break;
	case VIDEO_CTRL_PSP_DELETE:
		{
			lRet = IMOS_DelPreset(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, szChannel, nPresetIndex);
			if (ERR_COMMON_SUCCEED != lRet)
			{
				strTemp.LoadString(IDS_STRING315);
				PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPresetIndex, lRet);
                CString strTip;
				strTemp.LoadString(IDS_STRING316);
                strTip.Format(strTemp.GetBuffer(0), nPresetIndex, lRet);
                m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
                return lRet;
			}
		}		
		break;
	default:
		break;
	}
	strTemp.LoadString(IDS_STRING317);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));
	*/
	return VIDEO_SUCCESS;
}
/*
long CDVRFunc::VideoQueryPresetList(long nLoginID, char* szChannel, CVideoPSPList* plistPspInfo)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING318);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));

	long lRet;

	if (plistPspInfo == NULL)
	{
		strTemp.LoadString(IDS_STRING319);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	if ((szChannel == NULL) || (szChannel[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING320);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING321);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	ULONG ulBeginNum = 0;
	ULONG ulTotalNum = 0;
	int iItemIndex = 0;

	//�����ѯ����ڴ棬ÿ�β�DEMO_QUERY_PAGE_NUM��
	PRESET_INFO_S *pstPspList = NULL;
	pstPspList = (PRESET_INFO_S *)malloc(QUERY_PAGE_NUM * sizeof(PRESET_INFO_S));
	if (NULL == pstPspList)
	{
		strTemp.LoadString(IDS_STRING322);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}
	memset(pstPspList, 0, QUERY_PAGE_NUM * sizeof(PRESET_INFO_S));
	//plistFileInfo->clear();

	do 
	{
		QUERY_PAGE_INFO_S stQueryPageInfo = {0};
		stQueryPageInfo.bQueryCount = BOOL_TRUE;
		stQueryPageInfo.ulPageFirstRowNumber = ulBeginNum;
		stQueryPageInfo.ulPageRowNum = QUERY_PAGE_NUM;
		RSP_PAGE_INFO_S stRspPageInfo = {0};

		//����SDK�ӿڽ���Ԥ��λ��������ҳ��ѯ
		lRet = IMOS_QueryPresetList(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
			szChannel,
			&stQueryPageInfo,
			&stRspPageInfo,
			pstPspList);
		if (ERR_COMMON_SUCCEED != lRet)
		{
			free(pstPspList);
			strTemp.LoadString(IDS_STRING323);
			PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
            CString strTip;
			strTemp.LoadString(IDS_STRING324);
            strTip.Format(strTemp.GetBuffer(0), lRet);
            m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
            return lRet;
		}

		for (ULONG i = 0; i < stRspPageInfo.ulRowNum; i++)
		{
			// д��Ԥ��λ��Ϣ
			CVideoPSP thePsp;
			CString strTemp;
			strTemp.Format("Psp%d_%s", iItemIndex+1, szChannel);
			thePsp.SetName(strTemp);
			thePsp.SetPresetIndex(pstPspList[i].ulPresetValue);
			thePsp.SetDescription(pstPspList[i].szPresetDesc);
			plistPspInfo->InsertObject(thePsp);
			iItemIndex++;
		}

		ulTotalNum = stRspPageInfo.ulTotalRowNum;
		ulBeginNum += stRspPageInfo.ulRowNum;
		memset(pstPspList, 0, QUERY_PAGE_NUM * sizeof(PRESET_INFO_S));
		memset(&stRspPageInfo, 0, sizeof(RSP_PAGE_INFO_S));

	} while (ulTotalNum > ulBeginNum);

	free(pstPspList);
	strTemp.LoadString(IDS_STRING325);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));

	return VIDEO_SUCCESS;
}
*/
// �����豸���ƣ�������̨������ʵ��
long CDVRFunc::VideoAuxiliaryDeviceControl(long nPlayID, long nControlCode, long nSpeed, long lElpaseTime)
{
	/*CString strTemp;
	strTemp.LoadString(IDS_STRING326);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));

	if ((nPlayID < 0) || (nControlCode < 0) || (nSpeed < 0) || (lElpaseTime < 0))
	{
		strTemp.LoadString(IDS_STRING327);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	PPLAY_INFO pPlayInfo = NULL;
	bool bFound = GetPlayInfoByPlayID(nPlayID, pPlayInfo);
	if(!bFound)
	{
		strTemp.LoadString(IDS_STRING328);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nPlayID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nPlayID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(pPlayInfo->nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING329);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), pPlayInfo->nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	if(strcmp(pDeviceInfo->WindowInfo[pPlayInfo->nIMosPlayID].szChannel, "") == 0)
	{
		strTemp.LoadString(IDS_STRING330);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), pDeviceInfo->WindowInfo[pPlayInfo->nIMosPlayID].szChannel);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), pDeviceInfo->WindowInfo[nPlayID].szChannel);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	long lRet;

	lRet = IMOS_StartPtzCtrl(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->WindowInfo[pPlayInfo->nIMosPlayID].szChannel);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING331);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING332);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}

	PTZ_CTRL_COMMAND_S stPtzCtrlCmd = {0};
	stPtzCtrlCmd.ulPTZCmdPara1 = nSpeed;
	stPtzCtrlCmd.ulPTZCmdPara2 = nSpeed;

	if(nSpeed == 0)
	{
		switch (nControlCode)
		{
		case VIDEO_CTRL_AUX_BRUSH:
			stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_BRUSHOFF;
			break;
		case VIDEO_CTRL_AUX_HEATER:
			stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_HEATOFF;
			break;
		//case ��:
		//	stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_LIGHTOFF;
		//	break;
		//case ����:
		//	stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_INFRAREDOFF;
		//	break;
		default:
			break;
		}
	}
	else
	{
		switch (nControlCode)
		{
		case VIDEO_CTRL_AUX_BRUSH:
			stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_BRUSHON;
			break;
		case VIDEO_CTRL_AUX_HEATER:
			stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_HEATON;
			break;
		//case ��:
		//	stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_LIGHTON;
		//	break;
		//case ����:
		//	stPtzCtrlCmd.ulPTZCmdID = MW_PTZ_INFRAREDON;
		//	break;
		default:
			break;
		}
	}

	lRet = IMOS_PtzCtrlCommand(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->WindowInfo[pPlayInfo->nIMosPlayID].szChannel, &stPtzCtrlCmd);

	//�ͷſ���
	if(nSpeed == 0)
	{
		int nRet = IMOS_ReleasePtzCtrl(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, pDeviceInfo->WindowInfo[pPlayInfo->nIMosPlayID].szChannel, TRUE);
		if(nRet != ERR_COMMON_SUCCEED)
		{
			strTemp.LoadString(IDS_STRING333);
			PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nRet);
            CString strTip;
			strTemp.LoadString(IDS_STRING334);
            strTip.Format(strTemp.GetBuffer(0), nRet);
            m_pSetSDKErrInfoCallback(false, nRet, strTip.GetBuffer(0), 0, "");
		}
	}

	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING335);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR,strTemp.GetBuffer(0), lRet);
        CString strTip;
		strTemp.LoadString(IDS_STRING336);
        strTip.Format(strTemp.GetBuffer(0), lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	strTemp.LoadString(IDS_STRING337);
    PKLog.LogMessage(PK_LOGLEVEL_INFO, strTemp.GetBuffer(0));
	*/
	return VIDEO_SUCCESS;
}

// �л�����ͷ��������
long CDVRFunc::VideoSwitchCamToMon(long nLoginID, char* szChannel, char* szMonCode, char* szExtParam, long lExtSize)
{
	/*CString strTemp;
	if ((szChannel == NULL) || (szChannel[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING338);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	if ((szMonCode == NULL) || (szMonCode[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING339);
        PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTemp.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING340);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), nLoginID);
        m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
        return EC_PK_VIDEO_ADDIN_ERROR;
	}

	// ����ֹͣԭ���ļ�����
	long lRet = IMOS_StopMonitor(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, szMonCode, USER_OPERATE_SERVICE);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING341);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), szMonCode, lRet);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), szMonCode, lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        // ����Ҳ�����أ�ֱ��������
	}
   
    CString strSrc = szExtParam;
    CString strCameraCodeFlow = GetNextToken(strSrc);

    long lCodeFlow = VIDEO_CAMERA_MAIN_CODEFLOW;//����ģʽ 0�������� 1��������
    if (!strCameraCodeFlow.IsEmpty())
        lCodeFlow = atol(strCameraCodeFlow.GetBuffer(0));

    unsigned long ulStreamType = IMOS_FAVORITE_STREAM_ANY;/**< ��ָ�� 
    switch(lCodeFlow)
    {
    case VIDEO_CAMERA_MAIN_CODEFLOW:
        ulStreamType = IMOS_FAVORITE_STREAM_PRIMARY;/**< ָ������ 
        break;
    case VIDEO_CAMERA_SECOND_CODEFLOW:
        ulStreamType = IMOS_FAVORITE_STREAM_SECONDERY;/**< ָ������ 
        break;
    default:
        break;
    }

	// �л�������
	lRet = IMOS_StartMonitor(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
		szChannel,
		szMonCode,
		ulStreamType,
		USER_OPERATE_SERVICE);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING342);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), szChannel, szMonCode, lRet);
        CString strTip;
        strTip.Format(strTemp.GetBuffer(0), szChannel, szMonCode, lRet);
        m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
        return lRet;
	}
	*/
	return VIDEO_SUCCESS;
}

// ���ܲ���(��ΪԤ��)
long CDVRFunc::VideoGeneralControl(char* pszCtrlBuffer, long* pnSize)
{
	CString strTemp;
	strTemp.LoadString(IDS_STRING138);
    m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE, strTemp.GetBuffer(0), 0, "");
    return EC_PK_VIDEO_NOTIMPLEMENTEDCMDCODE;
}

// ���ò���ĳ�����Ϣ
void CDVRFunc::SetSDKErrInfoCallback(void (*pFuncSetSDKErrInfo)(bool bSDK, long lErrCode, const char* szErrMeg, long lSDKErrCode, const char* szSDKErrMeg))
{
    if (pFuncSetSDKErrInfo != NULL)
    {
        m_pSetSDKErrInfoCallback = pFuncSetSDKErrInfo;
    }
}

//�򿪲���������
long CDVRFunc::VideoPlaySound(long nLoginID,long nPlayID)
{
	//map<long, LPVOID>::iterator itLogin = m_mapLoginid2Handle.find(nLoginID);
	//if (itLogin == m_mapLoginid2Handle.end())  //��ʾû�в��ҵ���¼���
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoPlaySound Loginid invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}

	return VIDEO_SUCCESS;
}

//�رղ���������
long CDVRFunc::VideoStopSound(long nLoginID,long nPlayID)
{
	//map<long, LPVOID>::iterator itLogin = m_mapLoginid2Handle.find(nLoginID);
	//if (itLogin == m_mapLoginid2Handle.end())  //��ʾû�в��ҵ���¼���
	//{
	//	PKLog.LogMessage(PK_LOGLEVEL_ERROR, "DVRUNV VideoStopSound Loginid invaild");
	//	return EC_PK_VIDEO_MONITORNOTEXIST;
	//}

	return VIDEO_SUCCESS;
}
//��ȡϵͳ����ֵ
long CDVRFunc::VideoGetVolume(unsigned long* pVolume)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING352);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0));

	lRet = IMOS_GetVolume(pVolume);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING353);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING354);
		strTip.Format(strTemp.GetBuffer(0),lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}
//����ϵͳ����ֵ
long CDVRFunc::VideoSetVolume(long lVolume)
{
/*	long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING355);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),lVolume);

	if (lVolume<0||lVolume>255)
	{
		strTemp.LoadString(IDS_STRING356);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),lVolume);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0),lVolume);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	lRet = IMOS_SetVolume(lVolume);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING350);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lVolume, lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING351);
		strTip.Format(strTemp.GetBuffer(0),lVolume,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//��������ͨ��������С
long CDVRFunc::VideoAdjustAllWaveAudio(long nLoginID,long lVolume)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING359);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),nLoginID,lVolume);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING360);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0), nLoginID);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_ADDIN_ERROR;
	}
	if (lVolume<0||lVolume>255)
	{
		strTemp.LoadString(IDS_STRING356);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),lVolume);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0),lVolume);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	lRet = IMOS_AdjustAllWaveAudio(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,lVolume);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING361);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lVolume, lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING362);
		strTip.Format(strTemp.GetBuffer(0),lVolume,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//��ʼ˫�������Խ�
long CDVRFunc::VideoStartTalk(long nLoginID,char* szChannel)
{
/*	long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING363);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),nLoginID,szChannel);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING364);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0), nLoginID);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_ADDIN_ERROR;
	}
	if ((szChannel == NULL) || (szChannel[0] == '\0'))
	{
		strTemp.LoadString(IDS_STRING141);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0));
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0));
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}
	
	lRet = IMOS_StartVoiceTalk(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,szChannel,"",USER_OPERATE_SERVICE);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING365);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), szChannel, lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING366);
		strTip.Format(strTemp.GetBuffer(0),szChannel,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//ֹͣ˫�������Խ�
long CDVRFunc::VideoStopTalk(long nLoginID)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING367);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),nLoginID);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING368);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0), nLoginID);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_ADDIN_ERROR;
	}
	lRet = IMOS_StopVoiceTalk(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,"",USER_OPERATE_SERVICE);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING369);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING370);
		strTip.Format(strTemp.GetBuffer(0),lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//������ֹͣ��������������(����)
long CDVRFunc::VideoQuiet(long nLoginID,bool bQuiet)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING371);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),nLoginID,bQuiet);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING372);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0), nLoginID);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_ADDIN_ERROR;
	}
	/*
	char szXpCode[48] = {0};
	lRet = IMOS_GetChannelCode(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo, szXpCode);
	lRet = IMOS_SetPlayWnd(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,szXpCode,hWnd);
	lRet = IMOS_StartMonitor(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,
		"guobiao_168",
		szXpCode,
		IMOS_FAVORITE_STREAM_PRIMARY,
		USER_OPERATE_SERVICE);
	*/
	/*lRet = IMOS_VoiceQuiet(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,bQuiet);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING373);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),bQuiet,lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING374);
		strTip.Format(strTemp.GetBuffer(0),bQuiet,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//�����˷�����(0-255)
long CDVRFunc::VideoGetMicVolume(unsigned long* pVolume)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING375);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0));

	lRet = IMOS_GetMicVolume(pVolume);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING376);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING377);
		strTip.Format(strTemp.GetBuffer(0),lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}
//������˷�����(0-255)
long CDVRFunc::VideoSetMicVolume(long lVolume)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING378);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),lVolume);

	if (lVolume<0||lVolume>255)
	{
		strTemp.LoadString(IDS_STRING379);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),lVolume);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0),lVolume);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_FUNCPARAMINVALID, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_FUNCPARAMINVALID;
	}

	lRet = IMOS_SetMicVolume(lVolume);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING380);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), lVolume, lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING381);
		strTip.Format(strTemp.GetBuffer(0),lVolume,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}

//������ֹͣ�������Զ˷�����������
long CDVRFunc::VideoSendVoiceData(long nLoginID,bool bSend)
{
	/*long lRet=0;
	CString strTemp;
	strTemp.LoadString(IDS_STRING382);
	PKLog.LogMessage(PK_LOGLEVEL_INFO,strTemp.GetBuffer(0),nLoginID,bSend);

	PDEVICE_INFO pDeviceInfo = NULL;
	bool bLogged = GetDeviceByLoginID(nLoginID, pDeviceInfo);
	if(!bLogged)
	{
		strTemp.LoadString(IDS_STRING383);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0), nLoginID);
		CString strTip;
		strTip.Format(strTemp.GetBuffer(0), nLoginID);
		m_pSetSDKErrInfoCallback(false, EC_PK_VIDEO_ADDIN_ERROR, strTip.GetBuffer(0), 0, "");
		return EC_PK_VIDEO_ADDIN_ERROR;
	}
	lRet = IMOS_SendVoiceData(&pDeviceInfo->stLoginInfo.stUserLoginIDInfo,bSend);
	if (ERR_COMMON_SUCCEED != lRet)
	{
		strTemp.LoadString(IDS_STRING384);
		PKLog.LogMessage(PK_LOGLEVEL_ERROR, strTemp.GetBuffer(0),bSend,lRet);
		CString strTip;
		strTemp.LoadString(IDS_STRING385);
		strTip.Format(strTemp.GetBuffer(0),bSend,lRet);
		m_pSetSDKErrInfoCallback(false, lRet, strTip.GetBuffer(0), 0, "");
		return lRet;
	}*/
	return VIDEO_SUCCESS;
}
