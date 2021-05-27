#include "pch.h"
#include <Windows.h>
#include <Iphlpapi.h>  
#pragma comment(lib,"Iphlpapi.lib") 


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

namespace Felidae {

	BOOL GetIpAddr(char* data, size_t dataSize) {
		ULONG size = sizeof(IP_ADAPTER_INFO);
		PIP_ADAPTER_INFO pIpAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(sizeof(IP_ADAPTER_INFO));
		if (pIpAdapterInfo == NULL) {
			return FALSE;
		}
		ULONG result = GetAdaptersInfo(pIpAdapterInfo, &size);
		if (ERROR_BUFFER_OVERFLOW == result) {
			FREE(pIpAdapterInfo);
			pIpAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(size);
			result = GetAdaptersInfo(pIpAdapterInfo, &size);
		}
		if (result != ERROR_SUCCESS) {
			FREE(pIpAdapterInfo);
			return FALSE;
		}
		PIP_ADAPTER_INFO pAdapter = pIpAdapterInfo;
		while (pAdapter != NULL)
		{
			switch (pAdapter->Type)
			{
			case MIB_IF_TYPE_ETHERNET:
			case MIB_IF_TYPE_PPP:
			case MIB_IF_TYPE_FDDI:
			case IF_TYPE_IEEE80211:
				char addrBuf[17];
				memset(addrBuf, 0, 17);
				strcpy_s(addrBuf, 17, pAdapter->IpAddressList.IpAddress.String);
				if (strcmp("0.0.0.0", addrBuf) != 0) {
					size_t s = strlen(addrBuf);
					if (dataSize < s + 1) {
						FREE(pIpAdapterInfo);
						return FALSE;
					}
					memset(data, 0, dataSize);
					strcpy_s(data, dataSize, addrBuf);
					FREE(pIpAdapterInfo);
					return TRUE;
				}
			default:
				break;
			}
			pAdapter = pAdapter->Next;
		}
		FREE(pIpAdapterInfo);
		return FALSE;
	}


	void str_replace(char* data, char origin, char next) {
		int i = 0;
		while (true) {
			char c = data[i];
			if (c == 0) {
				break;
			}
			if (c == origin) {
				data[i] = next;
			}
			i++;
		}

	}

	BOOL GetIpAddrX(char* data, size_t dataSize, char delimiter) {
		if (GetIpAddr(data, dataSize)) {
			str_replace(data, '.', delimiter);
			return TRUE;
		}
		return FALSE;
	}
}