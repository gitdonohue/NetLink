//
// https://github.com/gitdonohue/NetLink
// MIT Licence
//

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
	NetLinkSocketClient();
	~NetLinkSocketClient();
	bool Connect(const char* server, int port);
	void StartConnect(const char* server, int port, int reconnectDelayMs = 3000); // Note: SleepMs callback must be implemented
	void Disconnect();

	bool IsConnected() const;
	bool SendCommand(const char* command);
	bool SendCommand(const NetLinkMessage& command);
	std::future<NetLinkMessage> SendQuery(const NetLinkMessage& msg);

	// Warning: The event handlers may be called from another thread
	std::function<void()> ConnectHandler;
	std::function<void()> DisconnectHandler;
	std::function<void(const NetLinkMessage&)> CommandHandler;
	std::function<NetLinkMessage(const NetLinkMessage&)> QueryHandler;

	std::function<void(int)> SleepMs;

private:
	void* m_pImpl;
};