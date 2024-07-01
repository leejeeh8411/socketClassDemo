#pragma once
#include <iostream>
#include <memory>
#include <vector>
#include "TcpIp.h"

using namespace std;



int main(void)
{
	TcpIp tcpIp;
	tcpIp.CreateTcpIp("172.30.1.86:8000", SocketType::Client);

	while (true)
	{
		tcpIp.SendData("M0\r\n");
		Sleep(100);
	}

	return 0;
}

