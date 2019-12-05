#ifndef CG_CATALOG_INFO_H
#define  CG_CATALOG_INFO_H
#include <string>

class CCatalogInfo
{
public:
	CCatalogInfo()
		: Address("")
		, DeviceID("")
		, IPAddress("")
		, componentid("")
		, Name("")
		, Manufacturer("")
		, Model("")
		, Owner("")
		, Civilcode("")
		, Safetyway(0)
		, Registerway(0)
		, Secrecy(0)
		,lastAccessTime(0)
		,Status("")
	{
	}

	~CCatalogInfo()
	{
	}

	CCatalogInfo(const CCatalogInfo& rhs)
	{
		Address = rhs.Address;
		DeviceID = rhs.DeviceID;
		IPAddress = rhs.IPAddress;
		componentid = rhs.componentid;
		Name = rhs.Name;
		Manufacturer = rhs.Manufacturer;
		Model = rhs.Model;
		Owner = rhs.Owner;
		Civilcode = rhs.Civilcode;
		Safetyway = rhs.Safetyway;
		Registerway = rhs.Registerway;
		Secrecy = rhs.Secrecy;
		PlatformAddr = rhs.PlatformAddr;
		PlatformPort = rhs.PlatformPort;
		lastAccessTime = rhs.lastAccessTime;
		Status = rhs.Status;
	}

	CCatalogInfo& operator=(const CCatalogInfo& rhs)
	{
		if (this == &rhs) return *this;

		Address = rhs.Address;
		DeviceID = rhs.DeviceID;
		IPAddress = rhs.IPAddress;
		componentid = rhs.componentid;
		Name = rhs.Name;
		Manufacturer = rhs.Manufacturer;
		Model = rhs.Model;
		Owner = rhs.Owner;
		Civilcode = rhs.Civilcode;
		Safetyway = rhs.Safetyway;
		Registerway = rhs.Registerway;
		Secrecy = rhs.Secrecy;
		PlatformAddr = rhs.PlatformAddr;
		PlatformPort = rhs.PlatformPort;
		lastAccessTime = rhs.lastAccessTime;
		Status = rhs.Status;
		return *this;
	}

	std::string Address;
	std::string DeviceID;
	std::string IPAddress;
	std::string componentid;
	std::string Name;
	std::string Manufacturer;
	std::string Model;
	std::string Owner;
	std::string Civilcode;
	int Safetyway;
	int Registerway;
	int Secrecy;
	std::string PlatformAddr;
	int PlatformPort;
	long long lastAccessTime;
	std::string Status;


};
#endif