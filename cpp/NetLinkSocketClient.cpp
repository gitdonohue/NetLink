#include "NetLinkSocketClient.hpp"

#include <string>
#include <vector>
#include <cstddef>
#include <iostream>
#include <thread>
#include <sstream>
#include <random>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#pragma comment(lib,"ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#else
typedef int SOCKET;
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

using namespace std;

#define VERBOSE 0

//////////////////////////////////////////////////////////////////////////
//
// Internal Definition of Implementation Class
//
//////////////////////////////////////////////////////////////////////////

struct GUID128
{ 
    uint64_t _low = 0;
    uint64_t _high = 0;
};

struct CompareGUID128
{
    bool operator()(const GUID128& a, const GUID128& b) const {
        return (a._high != b._high) ? (a._high < b._high) : (a._low < b._low);
    }
};

class NetLinkSocketClientImpl
{
private:
    NetLinkSocketClient& m_client;
    std::string m_serverAddress;
    int m_serverPort;
    bool m_bIsConnected = false;
    SOCKET m_socket = -1;

    GUID128 link_guid;

    volatile bool m_listenThreadShouldStop;
    std::thread* m_listenThread;

    std::map<GUID128, std::promise<NetLinkMessage>, CompareGUID128> m_pendingMessages;

public:
    NetLinkSocketClientImpl(const char* server, int port, NetLinkSocketClient& client)
        : m_serverAddress(server), m_serverPort(port), m_client(client), 
        m_listenThread(nullptr), m_listenThreadShouldStop(false),
        m_socket(-1), m_bIsConnected(false)
    {}

    ~NetLinkSocketClientImpl() { Disconnect(); }

    bool Connect();
    void Disconnect();
    bool IsConnected() { return m_bIsConnected; }
    bool SendCommand(const std::string& command);
    bool SendCommand(const NetLinkMessage& command);
    std::future<NetLinkMessage> SendQuery(const NetLinkMessage& msg);

private:
    void StartListening();
    bool InternalSendMessage(const NetLinkMessage& command, bool isQueryResponse, GUID128* guid);
    void HandlePacket(istream& packetstream);
    bool Send(void* buffer, int len);
    bool Receive(void* buffer, int len);
};

//////////////////////////////////////////////////////////////////////////
//
// PIMPL Mappings
//
//////////////////////////////////////////////////////////////////////////

NetLinkSocketClient::NetLinkSocketClient(const char* server, int port) { m_pImpl = new NetLinkSocketClientImpl(server, port, *this); }
bool NetLinkSocketClient::Connect() { return ((NetLinkSocketClientImpl*)m_pImpl)->Connect(); }
bool NetLinkSocketClient::SendCommand(const char* command) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendCommand(command); }
bool NetLinkSocketClient::SendCommand(const NetLinkMessage& command) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendCommand(command); }
void NetLinkSocketClient::Disconnect() { ((NetLinkSocketClientImpl*)m_pImpl)->Disconnect(); }
bool NetLinkSocketClient::IsConnected() { return ((NetLinkSocketClientImpl*)m_pImpl)->IsConnected(); }
std::future<NetLinkMessage> NetLinkSocketClient::SendQuery(const NetLinkMessage& msg) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendQuery(msg); }

//////////////////////////////////////////////////////////////////////////
//
// Internal Foreward declarations for utilities
//
//////////////////////////////////////////////////////////////////////////

void WriteByte(std::vector<std::byte>& buffer, std::byte val);
std::byte ReadByte(std::istream& istream);
void Write7BitEncodedInt(std::vector<std::byte>& buffer, int val);
int Read7BitEncodedInt(std::istream& istream);
void InsertDotNetString(std::vector<std::byte>& buffer, const std::string& val);
std::string ReadDotnetUtf8String(std::istream& istream);
GUID128 GenerateUUID();

//////////////////////////////////////////////////////////////////////////
//
// Internal implementation
//
//////////////////////////////////////////////////////////////////////////

bool NetLinkSocketClientImpl::Connect()
{
    Disconnect();

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) return false;
#endif

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* _addressInfo = nullptr;
    if (getaddrinfo(m_serverAddress.c_str(), std::to_string(m_serverPort).c_str(), &hints, &_addressInfo) != 0) return false;

    m_socket = socket(_addressInfo->ai_family, _addressInfo->ai_socktype, _addressInfo->ai_protocol);
    if (m_socket == -1) return false;

    if (connect(m_socket, _addressInfo->ai_addr, (int)_addressInfo->ai_addrlen)) 
    {
#if VERBOSE
        std::cerr << "Not Connected\n";
#endif
        Disconnect();
        return false;
    }

#if VERBOSE
    std::cout << "Connected\n";
#endif
    m_bIsConnected = true;

    Receive(&link_guid, 16);

    StartListening();

    return true;
}

void NetLinkSocketClientImpl::Disconnect()
{
    if (m_socket != -1)
    {
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
        m_socket = -1;
    }
    m_bIsConnected = false;

    m_listenThreadShouldStop = true;
    if (m_listenThread)
    {
        m_listenThread->join();
        m_listenThread = nullptr;
    }
}

bool NetLinkSocketClientImpl::Send(void* buffer, int len)
{
    if (!m_bIsConnected) return false;
    if (!buffer || len == 0) return false;
    int send_len = send(m_socket, (char*)buffer, len, 0);
    return send_len == len;
}

bool NetLinkSocketClientImpl::Receive(void* buffer, int len)
{
    if (!m_bIsConnected) return false;
    if (!buffer || len == 0) return false;
    int totalLen = len;
    int totalRecv = 0;
    char* recvPtr = (char*)buffer;
    while (len > 0)
    {
        int n = recv(m_socket, recvPtr, len, 0);
        if (n <= 0) return false;
        len -= n;
        totalRecv += n;
    }
    return totalRecv == totalLen;
}

// Stream from memory buffer
class membuf : public std::basic_streambuf<char> 
{
public:
    membuf(const std::byte* p, size_t l) { setg((char*)p, (char*)p, (char*)p + l); }
};

class memstream : public std::istream 
{
public:
    memstream(const std::byte* p, size_t l) : std::istream(&_buffer), _buffer(p, l) { rdbuf(&_buffer); }
private:
    membuf _buffer;
};

void NetLinkSocketClientImpl::StartListening()
{
    if (!m_listenThread)
    {
        m_listenThreadShouldStop = false;
        m_listenThread = new std::thread([&]()
            {
                while (!m_listenThreadShouldStop)
                {
                    int receiveSize;
                    if (!Receive(&receiveSize, 4)) break;

                    std::vector<std::byte> receiveBuffer(receiveSize);
                    if (!Receive(receiveBuffer.data(), receiveSize)) break;
                    memstream receiveBufferStream(receiveBuffer.data(), receiveSize);
                    HandlePacket(receiveBufferStream);
                }
            });
    }
}

void NetLinkSocketClientImpl::HandlePacket(istream& packetstream)
{
    NetLinkMessage m;

    std::byte flags = ReadByte(packetstream);

    int numHeaders = Read7BitEncodedInt(packetstream);
    for (int i = 0; i < numHeaders; ++i)
    {
        std::string k = ReadDotnetUtf8String(packetstream);
        std::string v = ReadDotnetUtf8String(packetstream);
        m.headers.emplace(k, v);
    }

    int dataSize = Read7BitEncodedInt(packetstream);
    m.data.resize(dataSize);
    packetstream.read((char*)m.data.data(), m.data.size());

    GUID128 guid;
    packetstream.read((char*)&guid, 16);

    bool isQuery = guid._low != 0 || guid._high != 0;

    bool isQueryResponse = ReadByte(packetstream) != std::byte(0);
    bool isValid = ReadByte(packetstream) != std::byte(0);
    
    if (isQueryResponse)
    {
        m.isSuccessful = isValid;

        // Find query in pending messages
        auto it = m_pendingMessages.find(guid);
        if (it != m_pendingMessages.end())
        {
            it->second.set_value(m);
            m_pendingMessages.erase(it);
        }
    }
    else if (isQuery)
    {
        NetLinkMessage response = m_client.QueryHandler(m);
        //memcpy(response.guid, &guid, 16);
        InternalSendMessage(response, true, &guid);
    }
    else // Command
    {
        m_client.CommandHandler(m);
    }

}

bool NetLinkSocketClientImpl::SendCommand(const std::string& command)
{
    NetLinkMessage m;
    m.data.assign((std::byte*)command.c_str(), (std::byte*)command.c_str() + command.length());
    return SendCommand(m);
}

bool NetLinkSocketClientImpl::SendCommand(const NetLinkMessage& command)
{
    return InternalSendMessage(command, false, nullptr);
}

bool NetLinkSocketClientImpl::InternalSendMessage(const NetLinkMessage& message, bool isQueryResponse, GUID128* guid)
{
    if (!m_bIsConnected) { return false; }

    std::vector<std::byte> messageBuffer;
    messageBuffer.reserve(1024);

    messageBuffer.resize((size_t)4); // Size will be set at the end

    WriteByte(messageBuffer, std::byte(0)); // No flags

    int numHeaders = (int)message.headers.size();
    Write7BitEncodedInt(messageBuffer, numHeaders);
    for (auto& item : message.headers)
    {
        InsertDotNetString(messageBuffer, item.first);
        InsertDotNetString(messageBuffer, item.second);
    }

    Write7BitEncodedInt(messageBuffer, (int)message.data.size());
    messageBuffer.insert(messageBuffer.end(), (std::byte*)message.data.data(), (std::byte*)message.data.data() + message.data.size());

    if (guid != nullptr)
    {
        messageBuffer.insert(messageBuffer.end(), (std::byte*)guid, ((std::byte*)guid) + 16);
    }
    else
    {
        messageBuffer.insert(messageBuffer.end(), 16, std::byte(0));
    }

    WriteByte(messageBuffer, (std::byte)isQueryResponse);
    WriteByte(messageBuffer, (std::byte)message.isSuccessful);

    // Send message to server
    int len = (int)messageBuffer.size() - 4;
    memcpy(messageBuffer.data(), &len, 4);
    
    Send(messageBuffer.data(), (int)messageBuffer.size());

    return true;
}

std::future<NetLinkMessage> NetLinkSocketClientImpl::SendQuery(const NetLinkMessage& query)
{
    // TODO: Handle cancellation

    std::promise<NetLinkMessage> response_promise;
    std::future<NetLinkMessage> response_future = response_promise.get_future();
    GUID128 guid = GenerateUUID();
    m_pendingMessages.emplace(guid, std::move(response_promise));
    InternalSendMessage(query, false, &guid);
    return response_future;
}

//////////////////////////////////////////////////////////////////////////
//
// Utils
//
//////////////////////////////////////////////////////////////////////////

static void WriteByte(std::vector<std::byte>& buffer, std::byte val)
{
    buffer.push_back(val);
}

static std::byte ReadByte(std::istream& istream)
{
    std::byte b;
    istream.read((char*)&b, 1);
    return b;
}

static void Write7BitEncodedInt(std::vector<std::byte>& buffer, int val)
{
    uint8_t indx = 0;
    char c;
    while (1)
    {
        c = val & 0x7F;
        if (val > 0x7F) { c |= 0x80; }
        buffer.push_back((std::byte)c);
        if (val <= 0x7F) break;
        val >>= 7;
    }
}

static int Read7BitEncodedInt(std::istream& istream)
{
    int v = 0;
    uint8_t indx = 0;
    char c;
    while (1)
    {
        istream.read(&c, 1);
        v |= (c & 0x7F) << indx;
        if ((c & 0x80) == 0) break;
        indx += 7;
    }
    return v;
}

static void InsertDotNetString(std::vector<std::byte>& buffer, const std::string& val)
{
    int len = (int)val.length(); // tmp - not utf8 proper
    std::byte* utf8data = (std::byte*)val.c_str(); // tmp - not utf8 proper

    Write7BitEncodedInt(buffer, len);
    buffer.insert(buffer.end(), utf8data, utf8data + len);
}

static std::string ReadDotnetUtf8String(std::istream& istream)
{
    int sz = Read7BitEncodedInt(istream);
    std::vector<char> buffer(sz+1);
    istream.read((char*)buffer.data(), sz);
    buffer[sz] = 0;

    // temp - not utf8 proper
    std::string str(buffer.data());
    return str;
}

static GUID128 GenerateUUID()
{
    GUID128 guid;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    guid._low = dis(gen);
    guid._high = dis(gen);
    return guid;
}