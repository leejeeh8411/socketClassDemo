#include "TcpIp.h"


UINT TcpIp::RecvProcessThread(LPVOID pParam)
{
	TcpIp* pPerent = (TcpIp*)pParam;
	DWORD dwRet = 0;

	while (true)
	{
		if (pPerent->socket_type_ == SocketType::Server)
		{
			string recvData = pPerent->RecvWaitServer();
		}
		else if (pPerent->socket_type_ == SocketType::Client)
		{
			string recvData = pPerent->RecvWaitClient();
		}
	}

	return 0;
}

TcpIp::TcpIp()
{
	WSADATA wsaData;
	cout << "Winsock StartUp" << endl;
	WORD wsok = WSAStartup(MAKEWORD(2, 2), &wsaData);

	InitializeCriticalSection(&criticalsection_);

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

bool TcpIp::StartRecvProcessThread()
{
	if (p_thread_ != NULL) {
		return false;
	}

	p_thread_ = new std::thread(RecvProcessThread, this);
	p_thread_->detach();

	return true;
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

		server_socket_ = pSocket;
		readBlockSockets_.emplace_back(pSocket);
		socket_type_ = socket_type;
		StartRecvProcessThread();
	}
	else if(socket_type == SocketType::Client)
	{
		int error = pSocket->Connect((const SocketAddress&)(*sockAddr.get()));
		if (error != SOCKET_ERROR)
		{
			socket_type_ = socket_type;
			readBlockSockets_.emplace_back(pSocket);
			string strData = "ABCD";
			int sendOK = pSocket->Send(strData.c_str(), strData.length());
			cout << "Send Msg" << endl;
			if (sendOK == SOCKET_ERROR)
			{
				cout << "Send Error" << endl;
			}
			StartRecvProcessThread();
		}
		else
		{
			cout << "Connect Error" << endl;
		}
	}

	return true;
}


void TcpIp::SendDataBroad(string data)
{
	for (const TCPSocketPtr& socket : readBlockSockets_)
	{
		socket->Send(data.c_str(), data.length());
	}
}

string TcpIp::RecvWaitClient()
{
	for (const TCPSocketPtr& socket : readBlockSockets_)
	{
		if (!Select(&readBlockSockets_, &readableSockets_, nullptr, nullptr, nullptr, nullptr))
			continue;
		{
			//GOOD_SEGMENT_SIZE : 1000
			char cData[1000];
			memset(cData, NULL, sizeof(char) * 1000);
			socket->Receive(cData, 1000);
			cout << "Client Recv id:" << socket->GetSocket() << ", Msg:" << cData << endl;
			string return_str = cData;

			RecvData recv_data;
			recv_data.socket_id_ = socket->GetSocket();
			recv_data.recv_data = cData;
			PushRecvCmdData(recv_data);

			return return_str;
		}
	}
}

string TcpIp::RecvWaitServer()
{
	if (!Select(&readBlockSockets_, &readableSockets_, nullptr, nullptr, nullptr, nullptr))
	{

	}

	string return_str;
	for (const TCPSocketPtr& socket : readableSockets_)
	{
		//���ο� ������ ������ listenSocket �� ����?
		if (socket == server_socket_)
		{
			SocketAddress newClientAddress;
			auto newSocket = server_socket_->Accept(newClientAddress);
			cout << "Connect New Client, socket id:" << newSocket->GetSocket() << endl;
			readBlockSockets_.emplace_back(newSocket);
			return return_str;
		}
		else
		{
			//GOOD_SEGMENT_SIZE : 1000
			char cData[1000];
			memset(cData, NULL, sizeof(char) * 1000);
			socket->Receive(cData, 1000);
			cout << "Client Recv id:" << socket->GetSocket() << ", Msg:" << cData << endl;
			return_str = cData;
			RecvData recv_data;
			recv_data.socket_id_ = socket->GetSocket();
			recv_data.recv_data = cData;
			PushRecvCmdData(recv_data);
			return return_str;
		}
	}
}

void TcpIp::PushRecvCmdData(RecvData recvData)
{
	EnterCriticalSection(&criticalsection_);

	vec_recv_data_.emplace_back(recvData);

	LeaveCriticalSection(&criticalsection_);

	cout << "PushRecvCmdData : " << recvData.recv_data << endl;
}

uint32_t TcpIp::GetRecvDataCount()
{
	return vec_recv_data_.size();
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

	//�����̸� ���ε� �Ѵ�
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
	printf("UDP ������ �����Ǿ����ϴ�.\n");

	// ���� �ּ� ����ü �ʱ�ȭ
	SOCKADDR_IN serveraddr;
	ZeroMemory(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(7000);
	serveraddr.sin_addr.s_addr = inet_addr("172.30.1.64");

	// ������ ��ſ� ����� ����
	SOCKADDR_IN peeraddr;
	int addrlen;
	char buf[BUFSIZE + 1];
	int len;
	for (int i = 0; i < 5; i++) {

		// ������ ������
		string strData = "ABCD";
		int retval = sendto(sock, strData.c_str(), strData.length(), 0, (SOCKADDR*)&serveraddr, sizeof(serveraddr));
		if (retval == SOCKET_ERROR) return;
		printf("[Ŭ���̾�Ʈ] %d����Ʈ�� ���½��ϴ�.\n", retval);

		//// ������ �ޱ�
		//addrlen = sizeof(peeraddr);
		//retval = recvfrom(sock, buf, BUFSIZE, 0,
		//	(SOCKADDR*)&peeraddr, &addrlen);
		//printf("������ ���� �����͸� �޾ҽ��ϴ�. \n\n");

		//// �۽����� IP �ּ� üũ
		//if (memcmp(&peeraddr, &serveraddr, sizeof(peeraddr)))
		//{
		//	printf("[����] �߸��� ������ �Դϴ�!\n");
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