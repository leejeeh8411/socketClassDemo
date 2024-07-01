#include "TcpIp.h"


TcpIp::TcpIp()
{
	WSADATA wsaData;
	cout << "Winsock StartUp" << endl;
	WORD wsok = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (wsok != 0)
	{
		cout << "Winsock Error" << endl;
	}

}
TcpIp::~TcpIp()
{
	cout << "Winsock CleanUp" << endl;
	WSACleanup();
}

//server
bool TcpIp::CreateTcpIp(string ip_address, SocketType socket_type)
{
	TCPSocketPtr pSocket(CreateTCPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr = SocketAddressFactory::CreateIPv4FromString(ip_address);

	if (socket_type == SocketType::Server)
	{
		if (pSocket->Bind((const SocketAddress&)(*sockAddr.get())) != NO_ERROR)
			return false;

		if (pSocket->Listen())
			return false;

		readBlockSockets_.emplace_back(pSocket);

		while (true)
		{
			if (!Select(&readBlockSockets_, &readableSockets_, nullptr, nullptr, nullptr, nullptr))
				continue;

			for (const TCPSocketPtr& socket : readableSockets_)
			{
				//새로운 연결이 들어오면 listenSocket 과 같다?
				if (socket == pSocket)
				{
					SocketAddress newClientAddress;
					auto newSocket = pSocket->Accept(newClientAddress);
					cout << "Connect New Client, socket id:" << newSocket->GetSocket() << endl;
					readBlockSockets_.emplace_back(newSocket);
				}
				else
				{
					//GOOD_SEGMENT_SIZE : 1000
					char cData[1000];
					memset(cData, NULL, sizeof(char) * 1000);
					socket->Receive(cData, 1000);
					cout << "Client Recv id:" << socket->GetSocket() << ", Msg:" << cData << endl;
				}
			}

			//send test
			for (const TCPSocketPtr& clients : readBlockSockets_)
			{
				string strData = "ABCD";
				clients->Send(strData.c_str(), strData.length());
			}
			Sleep(100);
		}
	}
	else if(socket_type == SocketType::Client)
	{
		int error = pSocket->Connect((const SocketAddress&)(*sockAddr.get()));
		if (error != SOCKET_ERROR)
		{
			readBlockSockets_.emplace_back(pSocket);
			string strData = "ABCD";
			int sendOK = pSocket->Send(strData.c_str(), strData.length());
			cout << "Send Msg" << endl;
			if (sendOK == SOCKET_ERROR)
			{
				cout << "Send Error" << endl;
			}
		}
		else
		{
			cout << "Connect Error" << endl;
		}
	}

	return true;
}


void TcpIp::SendData(string data)
{
	for (const TCPSocketPtr& clients : readBlockSockets_)
	{
		clients->Send(data.c_str(), data.length());
	}
}


void TcpIp::DoUdpLoop()
{
	UDPSocketPtr pUDP_send(CreateUDPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr_send = SocketAddressFactory::CreateIPv4FromString("172.30.1.64:7000");

	UDPSocketPtr pUDP_recv(CreateUDPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr_recv = SocketAddressFactory::CreateIPv4FromString("172.30.1.64:8000");

	string strData = "ABCD";
	int sendOK = pUDP_send->SendTo(strData.c_str(), strData.length(), (const SocketAddress&)(*sockAddr_send.get()));
	cout << "Send Msg" << endl;
	if (sendOK == SOCKET_ERROR)
	{
		cout << "Send Error" << endl;
	}

	//수신이면 바인드 한다
	int error = pUDP_recv->Bind((const SocketAddress&)(*sockAddr_recv.get()));
	if (error != SOCKET_ERROR)
	{
		char buf[BUFSIZE + 1];
		while (true)
		{
			int recvCnt = pUDP_recv->ReceiveFrom(buf, BUFSIZE, (SocketAddress&)(*sockAddr_recv.get()));

			if (recvCnt > 0)
			{
				cout << "Recv Data:" << buf << endl;
			}
		}
	}
	else
	{
		cout << "Bind Error" << endl;
	}
}

void TcpIp::DoUdpSendTest()
{
	// socket()
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) return;
	printf("UDP 소켓이 생성되었습니다.\n");

	// 소켓 주소 구조체 초기화
	SOCKADDR_IN serveraddr;
	ZeroMemory(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(7000);
	serveraddr.sin_addr.s_addr = inet_addr("172.30.1.64");

	// 데이터 통신에 사용할 변수
	SOCKADDR_IN peeraddr;
	int addrlen;
	char buf[BUFSIZE + 1];
	int len;
	for (int i = 0; i < 5; i++) {

		// 데이터 보내기
		string strData = "ABCD";
		int retval = sendto(sock, strData.c_str(), strData.length(), 0, (SOCKADDR*)&serveraddr, sizeof(serveraddr));
		if (retval == SOCKET_ERROR) return;
		printf("[클라이언트] %d바이트를 보냈습니다.\n", retval);

		//// 데이터 받기
		//addrlen = sizeof(peeraddr);
		//retval = recvfrom(sock, buf, BUFSIZE, 0,
		//	(SOCKADDR*)&peeraddr, &addrlen);
		//printf("서버로 부터 데이터를 받았습니다. \n\n");

		//// 송신자의 IP 주소 체크
		//if (memcmp(&peeraddr, &serveraddr, sizeof(peeraddr)))
		//{
		//	printf("[오류] 잘못된 데이터 입니다!\n");
		//	return;
		//}
	}
}

UDPSocketPtr TcpIp::CreateUDPSocket(SocketAddressFamily inFamily)
{
	SOCKET s = socket(inFamily, SOCK_DGRAM, IPPROTO_UDP);
	if (s != INVALID_SOCKET)
	{
		return UDPSocketPtr(new UDPSocket(s));
	}
	return nullptr;
}

TCPSocketPtr TcpIp::CreateTCPSocket(SocketAddressFamily inFamily)
{
	SOCKET s = socket(inFamily, SOCK_STREAM, IPPROTO_TCP);
	if (s != INVALID_SOCKET)
	{
		return TCPSocketPtr(new TCPSocket(s));
	}
	return nullptr;
}

fd_set* TcpIp::FillSetFromVector(fd_set& outSet, const vector<TCPSocketPtr>* inSockets)
{
	if (inSockets)
	{
		FD_ZERO(&outSet);
		for (const TCPSocketPtr& socket : *inSockets)
		{
			FD_SET(socket->GetSocket(), &outSet);
		}
		return &outSet;
	}
	else
	{
		return nullptr;
	}
}

void TcpIp::FillVectorFromSet(vector<TCPSocketPtr>* outSockets, const vector<TCPSocketPtr>* inSockets, const fd_set& inSet)
{
	if (inSockets && outSockets)
	{
		outSockets->clear();
		for (const TCPSocketPtr& socket : *inSockets)
		{
			if (FD_ISSET(socket->GetSocket(), &inSet))
				outSockets->emplace_back(socket);
		}
	}
}

int TcpIp::Select(const vector<TCPSocketPtr>* inReadSet, vector<TCPSocketPtr>* outReadSet, const vector<TCPSocketPtr>* inWriteSet, vector<TCPSocketPtr>* outWriteSet, const vector<TCPSocketPtr>* inExceptSet, vector<TCPSocketPtr>* outExceptSet)
{
	fd_set read, write, except;
	fd_set* readPtr = FillSetFromVector(read, inReadSet);
	fd_set* writePtr = FillSetFromVector(write, inWriteSet);
	fd_set* exceptPtr = FillSetFromVector(except, inExceptSet);
	int toRet = select(0, readPtr, writePtr, exceptPtr, nullptr);

	if (toRet > 0)
	{
		FillVectorFromSet(outReadSet, inReadSet, read);
		FillVectorFromSet(outWriteSet, inWriteSet, write);
		FillVectorFromSet(outExceptSet, inExceptSet, except);
	}
	return toRet;
}