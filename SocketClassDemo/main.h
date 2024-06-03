#pragma once
#include <iostream>
#include <WinSock2.h>
#include <memory>
#include <WS2tcpip.h>
#include <vector>

using namespace std;


class SocketAddress 
{
	
public:
	SocketAddress()
	{

	}
	SocketAddress(uint32_t adinAddress, uint8_t inPort)
	{
		GetAsSockAddrIn()->sin_family = AF_INET;
		GetAsSockAddrIn()->sin_addr.S_un.S_addr = htonl(adinAddress);
		GetAsSockAddrIn()->sin_port = htons(inPort);
		cout << "SocketAddress Constructor" << endl;
	}
	SocketAddress(const sockaddr& inSockAddr)
	{
		memcpy(&mSockAddr, &inSockAddr, sizeof(sockaddr));
	}

	~SocketAddress()
	{
		cout << "SocketAddress Destructor" << endl;
	}

	const sockaddr* GetAsSockAddr() const
	{
		return &mSockAddr;
	}

	size_t GetSize() const { return sizeof(sockaddr); }

private:
	sockaddr mSockAddr;

	sockaddr_in* GetAsSockAddrIn()
	{
		return reinterpret_cast<sockaddr_in*>(&mSockAddr);
	}
};

using SockAddressPtr = shared_ptr<SocketAddress>;


class SocketAddressFactory
{
public:
	static SockAddressPtr CreateIPv4FromString(const string& inString)
	{
		auto pos = inString.find_last_of(':');
		string host, service;
		if (pos != string::npos)
		{
			host = inString.substr(0, pos);
			service = inString.substr(pos + 1);
		}
		else
		{
			host = inString;
			service = "0";
		}

		addrinfo hint;
		memset(&hint, 0, sizeof(addrinfo));
		hint.ai_family = AF_INET;

		addrinfo* result = nullptr;
		int error = getaddrinfo(host.c_str(), service.c_str(),
			&hint, &result);
		addrinfo* initResult = result;

		if (error != 0 || result == nullptr)
		{
			freeaddrinfo(initResult);
			return nullptr;
		}

		while (!result->ai_addr && result->ai_next)
		{
			result = result->ai_next;
		}

		if (!result->ai_addr)
		{
			freeaddrinfo(initResult);
			return nullptr;
		}

		auto toRet = std::make_shared<SocketAddress>(*result->ai_addr);

		freeaddrinfo(initResult);
		return toRet;
	}
};

enum SocketAddressFamily
{
	INET = AF_INET,
	INET6 = AF_INET6
};



class UDPSocket
{
public:
	UDPSocket(SOCKET inSocket) : mSocket{ inSocket } 
	{
		cout << "Create UDP Socket" << endl;
	}

	~UDPSocket()
	{
		closesocket(mSocket);
		cout << "Close UDP Socket" << endl;
	}
	int Bind(const SocketAddress& inToAddress)
	{
		if (&inToAddress == nullptr)
		{
			return -1;
		}
		int err = bind(mSocket, inToAddress.GetAsSockAddr(), inToAddress.GetSize());
		if (err == SOCKET_ERROR)
		{
			cout << "Bind Error" << endl;
			return -1;
			
		}
		return NO_ERROR;
	}
	int SendTo(const void* inData, int inLen, const SocketAddress& inTo)
	{
		int byteSentCount = sendto(mSocket, static_cast<const char*>(inData), inLen, 0, inTo.GetAsSockAddr(), inTo.GetSize());

		if (byteSentCount >= 0)
		{
			return byteSentCount;
		}
		return -1;
	}
	int ReceiveFrom(void* inBuffer, int inMaxLength, SocketAddress& outFrom)
	{
		int fromLength = outFrom.GetSize();
		int readByteCount = recvfrom(mSocket, static_cast<char*>(inBuffer), inMaxLength, 0, (sockaddr*)outFrom.GetAsSockAddr(), &fromLength);

		if (readByteCount >= 0) 
		{
			return readByteCount;
		}
		return -1;
	}
private:
	
	SOCKET mSocket;
};

using UDPSocketPtr = shared_ptr<UDPSocket>;

UDPSocketPtr CreateUDPSocket(SocketAddressFamily inFamily)
{
	SOCKET s = socket(inFamily, SOCK_DGRAM, IPPROTO_UDP);
	if (s != INVALID_SOCKET)
	{
		return UDPSocketPtr(new UDPSocket(s));
	}
	return nullptr;
}

class TCPSocket;
using TCPSocketPtr = shared_ptr<TCPSocket>;

class TCPSocket
{
public:
	TCPSocket(SOCKET inSocket) : mSocket{ inSocket } {};
	~TCPSocket()
	{
		closesocket(mSocket);
		cout << "Close TCP Socket" << endl;
	}
	int Connect(const SocketAddress& inAddress)
	{
		int err = connect(mSocket, inAddress.GetAsSockAddr(), inAddress.GetSize());
		if (err >= 0)
			return mSocket;
	}
	int Bind(const SocketAddress& inToAddress)
	{
		if (&inToAddress == nullptr)
		{
			return -1;
		}
		int err = bind(mSocket, inToAddress.GetAsSockAddr(), inToAddress.GetSize());
		if (err == SOCKET_ERROR)
		{
			cout << "Bind Error" << endl;
			return -1;

		}
		return NO_ERROR;
	}
	int Listen(int inBackLog = 32)
	{
		int err = listen(mSocket, inBackLog);
		if (err >= 0)
		{
			return NO_ERROR;
		}

		return -1;
	}
	TCPSocketPtr Accept(SocketAddress& inFromAddress)
	{
		int length = inFromAddress.GetSize();
		SOCKET newSocket = accept(mSocket, (sockaddr*)inFromAddress.GetAsSockAddr(), &length);

		if (newSocket != INVALID_SOCKET)
		{
			return TCPSocketPtr(new TCPSocket(newSocket));
		}
	}
	int Send(const void* inData, int inLen)
	{
		int bytesSentCount = send(mSocket, static_cast<const char*>(inData), inLen, 0);

		if (bytesSentCount >= 0)
		{
			return bytesSentCount;
		}
		else
		{
			return SOCKET_ERROR;
		}
	}
	int Receive(void* inBuffer, int inLen)
	{
		int byteReceiveCount = recv(mSocket, static_cast<char*>(inBuffer), inLen, 0);

		if (byteReceiveCount >= 0)
		{
			return byteReceiveCount;
		}

		return -1;
	}

	SOCKET& GetSocket()
	{
		return mSocket;
	}

private:
	
	SOCKET mSocket;
};




TCPSocketPtr CreateTCPSocket(SocketAddressFamily inFamily)
{
	SOCKET s = socket(inFamily, SOCK_STREAM, IPPROTO_TCP);
	if (s != INVALID_SOCKET)
	{
		return TCPSocketPtr(new TCPSocket(s));
	}
	return nullptr;
}

fd_set* FillSetFromVector(fd_set& outSet, const vector<TCPSocketPtr>* inSockets)
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

void FillVectorFromSet(vector<TCPSocketPtr>* outSockets, const vector<TCPSocketPtr>* inSockets, const fd_set& inSet)
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

int Select(const vector<TCPSocketPtr>* inReadSet, vector<TCPSocketPtr>* outReadSet, const vector<TCPSocketPtr>* inWriteSet, vector<TCPSocketPtr>* outWriteSet, const vector<TCPSocketPtr>* inExceptSet, vector<TCPSocketPtr>* outExceptSet)
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

void DoTCPLoop()
{
	TCPSocketPtr listenSocket(CreateTCPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr = SocketAddressFactory::CreateIPv4FromString("59.18.216.121:8000");

	if (listenSocket->Bind((const SocketAddress&)(*sockAddr.get())) != NO_ERROR)
		return;

	if (listenSocket->Listen())
		return;
	
	//TCPSocketPtr listenSocket = CreateTCPSocket(INET);
	//SocketAddress receiveingAddress(INADDR_ANY, 8000);
	//if (listenSocket->Bind(receiveingAddress) != NO_ERROR)
	//	return;

	vector<TCPSocketPtr> readBlockSockets;
	readBlockSockets.emplace_back(listenSocket);
	vector<TCPSocketPtr> readableSockets;

	while (true)
	{
		if (!Select(&readBlockSockets, &readableSockets, nullptr, nullptr, nullptr, nullptr))
			continue;

		for (const TCPSocketPtr& socket : readableSockets)
		{
			if (socket == listenSocket)
			{
				SocketAddress newClientAddress;
				auto newSocket = listenSocket->Accept(newClientAddress);
				cout << "Connect New Client" << endl;
				readBlockSockets.emplace_back(newSocket);
			}
			else
			{
				char cData[1000];
				memset(cData, NULL, sizeof(char) * 1000);
				socket->Receive(cData, 1000);
				cout << "Socket Msg:" << cData << endl;
			}
		}
		Sleep(100);
	}
}

void DoTCPTestCode()
{
	TCPSocketPtr pTCP(CreateTCPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr = SocketAddressFactory::CreateIPv4FromString("59.18.216.121:8000");
	int error = pTCP->Connect((const SocketAddress&)(*sockAddr.get()));
	if (error != SOCKET_ERROR)
	{
		string strData = "ABCD";
		int sendOK = pTCP->Send(strData.c_str(), strData.length());
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

void DoUDPTestCode()
{
	UDPSocketPtr pUDP(CreateUDPSocket(SocketAddressFamily::INET));
	SockAddressPtr sockAddr = SocketAddressFactory::CreateIPv4FromString("59.18.216.121:8000");
	int error = pUDP->Bind((const SocketAddress&)(*sockAddr.get()));
	if (error != SOCKET_ERROR)
	{
		string strData = "ABCD";
		int sendOK = pUDP->SendTo(strData.c_str(), strData.length(), (const SocketAddress&)(*sockAddr.get()));
		cout << "Send Msg" << endl;
		if (sendOK == SOCKET_ERROR)
		{
			cout << "Send Error" << endl;
		}
	}
	else
	{
		cout << "Bind Error" << endl;
	}
}

int main(void)
{
	WSADATA wsaData;
	cout << "Winsock StartUp" << endl;
	WORD wsok = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (wsok != 0)
	{
		cout << "Winsock Error" << endl;
	}

	//DoTCPTestCode();
	//DoUDPTestCode();
	DoTCPLoop();

	cout << "Winsock CleanUp" << endl;
	WSACleanup();

		
	return 0;
}

