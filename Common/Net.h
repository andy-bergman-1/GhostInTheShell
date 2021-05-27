#pragma once

#include <Windows.h>

namespace Felidae {
	BOOL GetIpAddr(char* data, size_t dataSize);
	BOOL GetIpAddrX(char* data, size_t dataSize, char delimiter);
}