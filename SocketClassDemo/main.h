#pragma once
#include <iostream>
#include <memory>
#include <vector>
#include "TcpIp.h"

using namespace std;



int main(void)
{
	TcpIp tcpIp;
	tcpIp.CreateTcpIp("172.30.1.86:8000", SocketType::Server);

	while (true)
	{
		tcpIp.SendDataBroad("M0\r\n");
		Sleep(1000);
	}

	return 0;
}

