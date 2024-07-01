#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <memory>
#include <vector>
#include <iostream>
#include <thread>

#define BUFSIZE 100

using namespace std;

enum SocketAddressFamily
{
	INET = AF_INET,
	INET6 = AF_INET6
};

enum SocketType
{
	Server = 0,
	Client,
};

static const uint32_t MAX_RECV_BUFFER = 1000;

struct RecvData
{
	uint8_t socket_id_;
	string recv_data;

	RecvData()
	{
		ResetData();
	}

	void ResetData()
	{
		socket_id_ = 0;
		recv_data.clear();
	}
};

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
		int err = ::bind(mSocket, inToAddress.GetAsSockAddr(), inToAddress.GetSize());
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

		int err = ::bind(mSocket, inToAddress.GetAsSockAddr(), inToAddress.GetSize());
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

class TcpIp
{
public:
	TcpIp();
	~TcpIp();
	bool CreateTcpIp(string ip_address, SocketType socket_type);
	void SendDataBroad(string data);
	string RecvWaitClient();
	string RecvWaitServer();
	uint32_t GetRecvDataCount();

	void DoUdpLoop();
	void DoUdpSendTest();
private:
	SocketType socket_type_;
	TCPSocketPtr server_socket_;
	vector<TCPSocketPtr> readBlockSockets_;
	vector<TCPSocketPtr> readableSockets_;
	vector<RecvData> vec_recv_data_;

	CRITICAL_SECTION    criticalsection_;

	std::thread* p_thread_;
	static UINT	RecvProcessThread(LPVOID pParam);
	bool StartRecvProcessThread();

	

	void PushRecvCmdData(RecvData recvData);
	UDPSocketPtr CreateUDPSocket(SocketAddressFamily inFamily);
	TCPSocketPtr CreateTCPSocket(SocketAddressFamily inFamily);
	fd_set* FillSetFromVector(fd_set& outSet, const vector<TCPSocketPtr>* inSockets);
	void FillVectorFromSet(vector<TCPSocketPtr>* outSockets, const vector<TCPSocketPtr>* inSockets, const fd_set& inSet);
	int Select(const vector<TCPSocketPtr>* inReadSet, vector<TCPSocketPtr>* outReadSet, const vector<TCPSocketPtr>* inWriteSet, vector<TCPSocketPtr>* outWriteSet, const vector<TCPSocketPtr>* inExceptSet, vector<TCPSocketPtr>* outExceptSet);
};



