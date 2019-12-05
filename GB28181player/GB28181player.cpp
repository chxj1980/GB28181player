// GB28181player.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "DVRFunc.h"

CDVRFunc g_DVRFunc;
extern "C" long __declspec(dllexport) Init(){
	return  g_DVRFunc.nInit();
}

extern "C" long __declspec(dllexport) login(std::string localip, std::string localport, long &nloginID){
	return g_DVRFunc.nlogin(localip, localport, nloginID);
}

extern "C" long __declspec(dllexport) startplay(long &nLoginID, char* szChannel, HWND hWnd, long nCodeFlow, long &nPlayID){
	return g_DVRFunc.nstartplay(nLoginID, szChannel, hWnd, nCodeFlow, nPlayID);
}

extern "C" long __declspec(dllexport) stopplay(long &nPlayID){
	return g_DVRFunc.nstopplay(nPlayID);
}
