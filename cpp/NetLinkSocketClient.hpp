#pragma once

#include <cstddef>
#include <vector>
#include <map>
#include <string>
#include <functional>
#include <future>

// Note: strings used in the messages should only contain ASCII characters, full utf8 is not supported.

struct NetLinkMessage
{
	std::vector<std::byte> data;
	std::map<std::string, std::string> headers;
	bool isSuccessful = false;
};

class NetLinkSocketClient
{
public:
	NetLinkSocketClient(const char* server, int port);
	bool Connect();
	void Disconnect();
	bool IsConnected();
	bool SendCommand(const char* command);
	bool SendCommand(const NetLinkMessage& command);
	std::future<NetLinkMessage> SendQuery(const NetLinkMessage& msg);

	std::function<void(const NetLinkMessage&)> CommandHandler; // Note: will be called from another thread
	std::function<NetLinkMessage(const NetLinkMessage&)> QueryHandler; // Note: will be called from another thread

private:
	void* m_pImpl;
};