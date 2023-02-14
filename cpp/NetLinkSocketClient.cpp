//
// https://github.com/gitdonohue/NetLink
// MIT Licence
//

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
    bool m_bIsConnected = false;
    SOCKET m_socket = -1;

    GUID128 link_guid;

    volatile bool m_connectThreadShouldStop = false;
    std::thread* m_connectThread = nullptr;

    volatile bool m_listenThreadShouldStop = false;
    std::thread* m_listenThread = nullptr;

    std::map<GUID128, std::promise<NetLinkMessage>, CompareGUID128> m_pendingMessages;

public:
    NetLinkSocketClientImpl(NetLinkSocketClient& client)
        : m_client(client), m_socket(-1), m_listenThread(nullptr), m_connectThread(nullptr)
    {}

    ~NetLinkSocketClientImpl() { Disconnect(); }

    bool Connect(const char* server, int port);
    void StartConnect(const char* server, int port, int reconnectDelyayMs);
    void Disconnect();
    bool IsConnected() const { return m_bIsConnected; }
    bool SendCommand(const std::string& command);
    bool SendCommand(const NetLinkMessage& command);
    std::future<NetLinkMessage> SendQuery(const NetLinkMessage& msg);

private:
    void StartListening();
    void StopListening();
    void StopConnect();
    void CloseSocket();
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

NetLinkSocketClient::NetLinkSocketClient() { m_pImpl = new NetLinkSocketClientImpl(*this); }
NetLinkSocketClient::~NetLinkSocketClient() { if (m_pImpl) { delete (NetLinkSocketClientImpl*)m_pImpl; m_pImpl = nullptr; } }
bool NetLinkSocketClient::Connect(const char* server, int port) { return ((NetLinkSocketClientImpl*)m_pImpl)->Connect(server, port); }
void NetLinkSocketClient::StartConnect(const char* server, int port, int reconnectDelyayMs) { ((NetLinkSocketClientImpl*)m_pImpl)->StartConnect(server, port, reconnectDelyayMs); }
bool NetLinkSocketClient::SendCommand(const char* command) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendCommand(command); }
bool NetLinkSocketClient::SendCommand(const NetLinkMessage& command) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendCommand(command); }
void NetLinkSocketClient::Disconnect() { ((NetLinkSocketClientImpl*)m_pImpl)->Disconnect(); }
bool NetLinkSocketClient::IsConnected() const { return ((NetLinkSocketClientImpl*)m_pImpl)->IsConnected(); }
std::future<NetLinkMessage> NetLinkSocketClient::SendQuery(const NetLinkMessage& msg) { return ((NetLinkSocketClientImpl*)m_pImpl)->SendQuery(msg); }

//////////////////////////////////////////////////////////////////////////
//
// Internal Forward declarations for utilities
//
//////////////////////////////////////////////////////////////////////////

void WriteByte(std::vector<std::byte>&, std::byte);
std::byte ReadByte(std::istream&);
void Write7BitEncodedInt(std::vector<std::byte>&, int);
int Read7BitEncodedInt(std::istream&);
void InsertDotNetString(std::vector<std::byte>&, const std::string&);
std::string ReadDotnetUtf8String(std::istream&);
GUID128 GenerateUUID();

//////////////////////////////////////////////////////////////////////////
//
// Internal implementation
//
//////////////////////////////////////////////////////////////////////////

bool NetLinkSocketClientImpl::Connect(const char* server, int port)
{
    CloseSocket();

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) return false;
#endif

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* _addressInfo = nullptr;
    if (getaddrinfo(server, std::to_string(port).c_str(), &hints, &_addressInfo) != 0) return false;

    m_socket = socket(_addressInfo->ai_family, _addressInfo->ai_socktype, _addressInfo->ai_protocol);
    if (m_socket == -1) return false;

    if (connect(m_socket, _addressInfo->ai_addr, static_cast<int>(_addressInfo->ai_addrlen)))
    {
#if VERBOSE
        std::cerr << "Not Connected\n";
#endif
        CloseSocket();
        return false;
    }

#if VERBOSE
    std::cout << "Connected\n";
#endif
    m_bIsConnected = true;

    Receive(&link_guid, 16);

    StartListening();

    if (m_client.ConnectHandler) m_client.ConnectHandler();

    return true;
}

void NetLinkSocketClientImpl::StartConnect(const char* server, int port, int reconnectDelyayMs)
{
    StopConnect();
    if (!m_connectThread)
    {
        m_connectThreadShouldStop = false;
        std::string serverName(server);
        m_connectThread = new std::thread([this, serverName, port, reconnectDelyayMs]()
        {
            while (!m_connectThreadShouldStop)
            {
                if (IsConnected())
                {
                    if (m_client.SleepMs) m_client.SleepMs(200);
                }
                else
                {
                    if (!Connect(serverName.c_str(), port))
                    {
                        if (m_client.SleepMs) m_client.SleepMs(reconnectDelyayMs);
                    }
                }
            }
        });
    }
}

void NetLinkSocketClientImpl::StopConnect()
{
    m_connectThreadShouldStop = true;
    if (m_connectThread)
    {
        m_connectThread->join();
        m_connectThread = nullptr;
    }
}

void NetLinkSocketClientImpl::CloseSocket()
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
}

void NetLinkSocketClientImpl::Disconnect()
{
    m_bIsConnected = false;
    StopConnect();
    StopListening();
    CloseSocket();
}

bool NetLinkSocketClientImpl::Send(void* buffer, int len)
{
    if (!m_bIsConnected) return false;
    if (!buffer || len == 0) return false;
    const int send_len = send(m_socket, static_cast<char*>(buffer), len, 0);
    return send_len == len;
}

bool NetLinkSocketClientImpl::Receive(void* buffer, int len)
{
    if (!m_bIsConnected) return false;
    if (!buffer || len == 0) return false;
    const int totalLen = len;
    int totalRecv = 0;
    char* recvPtr = static_cast<char*>(buffer);
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
    StopListening();
    m_listenThreadShouldStop = false;
    if (!m_listenThread)
    {
        m_listenThread = new std::thread([this]()
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

            this->m_bIsConnected = false;
            if (m_client.DisconnectHandler) m_client.DisconnectHandler();
        });
    }
}

void NetLinkSocketClientImpl::StopListening()
{
    m_listenThreadShouldStop = true;
    if (m_listenThread)
    {
        m_listenThread->join();
        m_listenThread = nullptr;
    }
}

void NetLinkSocketClientImpl::HandlePacket(istream& packetstream)
{
    NetLinkMessage m;

    std::byte flags = ReadByte(packetstream);

    const int numHeaders = Read7BitEncodedInt(packetstream);
    for (int i = 0; i < numHeaders; ++i)
    {
        std::string k = ReadDotnetUtf8String(packetstream);
        std::string v = ReadDotnetUtf8String(packetstream);
        m.headers.emplace(k, v);
    }

    const int dataSize = Read7BitEncodedInt(packetstream);
    m.data.resize(dataSize);
    packetstream.read(reinterpret_cast<char*>(m.data.data()), m.data.size());

    GUID128 guid;
    packetstream.read(reinterpret_cast<char*>(&guid), 16);

    const bool isQuery = guid._low != 0 || guid._high != 0;

    const bool isQueryResponse = ReadByte(packetstream) != std::byte(0);
    const bool isValid = ReadByte(packetstream) != std::byte(0);

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
        if (m_client.QueryHandler)
        {
            const NetLinkMessage response = m_client.QueryHandler(m);
            InternalSendMessage(response, true, &guid);
        }
        else
        {
            NetLinkMessage response;
            response.headers["error"] = "No query handler is set.";
            InternalSendMessage(response, false, &guid);
        }
    }
    else // Command
    {
        if (m_client.CommandHandler) m_client.CommandHandler(m);
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

    messageBuffer.resize(static_cast<size_t>(4)); // Size will be set at the end

    WriteByte(messageBuffer, static_cast<std::byte>(0)); // No flags

    const int numHeaders = static_cast<int>(message.headers.size());
    Write7BitEncodedInt(messageBuffer, numHeaders);
    for (auto& item : message.headers)
    {
        InsertDotNetString(messageBuffer, item.first);
        InsertDotNetString(messageBuffer, item.second);
    }

    Write7BitEncodedInt(messageBuffer, static_cast<int>(message.data.size()));
    messageBuffer.insert(messageBuffer.end(), (std::byte*)message.data.data(), (std::byte*)message.data.data() + message.data.size());

    if (guid != nullptr)
    {
        messageBuffer.insert(messageBuffer.end(), (std::byte*)guid, ((std::byte*)guid) + 16);
    }
    else
    {
        messageBuffer.insert(messageBuffer.end(), 16, std::byte(0));
    }

    WriteByte(messageBuffer, static_cast<std::byte>(isQueryResponse));
    WriteByte(messageBuffer, static_cast<std::byte>(message.isSuccessful));

    // Send message to server
    const int len = static_cast<int>(messageBuffer.size()) - 4;
    memcpy(messageBuffer.data(), &len, 4);

    if (!Send(messageBuffer.data(), static_cast<int>(messageBuffer.size())))
    {
        m_bIsConnected = false;
        StopListening();
        CloseSocket();
        return false;
    }

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

void WriteByte(std::vector<std::byte>& buffer, std::byte val)
{
    buffer.push_back(val);
}

std::byte ReadByte(std::istream& istream)
{
    std::byte b;
    istream.read(reinterpret_cast<char*>(&b), 1);
    return b;
}

void Write7BitEncodedInt(std::vector<std::byte>& buffer, int val)
{
    uint8_t indx = 0;
    char c;
    while (true)
    {
        c = val & 0x7F;
        if (val > 0x7F) { c |= 0x80; }
        buffer.push_back(static_cast<std::byte>(c));
        if (val <= 0x7F) break;
        val >>= 7;
    }
}

int Read7BitEncodedInt(std::istream& istream)
{
    int v = 0;
    uint8_t indx = 0;
    char c;
    while (true)
    {
        istream.read(&c, 1);
        v |= (c & 0x7F) << indx;
        if ((c & 0x80) == 0) break;
        indx += 7;
    }
    return v;
}

void InsertDotNetString(std::vector<std::byte>& buffer, const std::string& val)
{
    const int len = static_cast<int>(val.length()); // tmp - not utf8 proper
    std::byte* utf8data = (std::byte*)val.c_str(); // tmp - not utf8 proper

    Write7BitEncodedInt(buffer, len);
    buffer.insert(buffer.end(), utf8data, utf8data + len);
}

std::string ReadDotnetUtf8String(std::istream& istream)
{
    const int sz = Read7BitEncodedInt(istream);
    std::vector<char> buffer(sz + 1);
    istream.read((char*)buffer.data(), sz);
    buffer[sz] = 0;

    // temp - not utf8 proper
    std::string str(buffer.data());
    return str;
}

GUID128 GenerateUUID()
{
    GUID128 guid;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    guid._low = dis(gen);
    guid._high = dis(gen);
    return guid;
}