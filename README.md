# NetLink

NetLink Client-Server Helper Library for .Net/C#.

## Description

A helper library to establish client-server links of over different transports (tcp-sockets/named-pipes/web-sockets/...).

NetLink is a simple way to establish a network link between a server and client(s), and have commands and queries be sent asynchronously between both.
This can be used for simple IPC, or to manage remote connections.

## Features

- Simple integration
- Connection-based links
- Commands and Queries
- Bi-directional, asynchronous
- Strings, headers and byte array payloads
- Works over TCP Sockets, WebSockets or Named Pipes
- link-level Compression
- link-level Encryption and/or Validation (using X509 Certificates)
- Clients in C#, C++ and Javascript

## Nuget

The nuget package can be found at: https://www.nuget.org/packages/NetLink

## Examples

The following examples can be found in https://github.com/gitdonohue/NetLink/blob/develop/Examples.

### Client Examples

A client link can be created via the ```NetLinkSocket```, ```NetLinkNamedPipe``` or ```NetLinkWebsocket``` classes, to connect to a server. For example:
```
INetLink netlinkCLient = new NetLinkSocket(server: "localhost", port: 4445);
```

In order to handle events, ```CommandHandler``` and ```QueryHandler``` event handlers can be bound:
```
netlinkCLient.CommandHandler = async (INetLink link, NetMessage command, CancellationToken ct) =>
{
    Console.WriteLine($"Client Processing command: {command.GetCommand()}");
    await Task.Delay(100, ct); // some work here...
};

netlinkCLient.QueryHandler = async (INetLink link, NetMessage query, CancellationToken ct) =>
{
    await Task.Delay(100, ct); // some work here...
    var resp = link.CreateResponse(query, true, "Client OK");
    return resp;
};
```

The ```SendCommand()``` and ```SendQuery()``` methods can be used to send to the server. For example:
```
await netlinkCLient.SendCommand(netlinkCLient.CreateCommand("clientToServerCommand"), ct);

var serverResponse = await netlinkCLient.SendQuery(netlinkCLient.CreateQuery("clientToServerQuery").AddHeader("headerName","headerValue"), ct);
Console.WriteLine($"Server response: {serverResponse.GetResponse()}");
```

### Server Examples

A server endpoint can be created using the ```NetLinkSocketServer```, ```NetLinkWebsocketServer``` or ```NetLinkNamedPipeServer``` classes, for example:
```
var netLinkServer = new NetLinkSocketServer(port: 4444, server: "auto");
```

The server could accept connections using several methods by using the ```NetLinkAggregateServer``` class, for example:
```
var netLinkServer = new NetLinkAggregateServer(new List<INetLinkServer>()
{
    new NetLinkSocketServer(port: 4444, server: "auto"),
    new NetLinkSocketServer(port: 4445, server: "localhost") { AllowEncryption = false },
    new NetLinkSocketServer(port: 4446, server: "127.0.0.1") { AllowEncryption = false },
    new NetLinkNamedPipeServer(pipeName: @"Netlink\NetlinkNamedPipeServerExample"),
    new NetLinkWebsocketServer(port: 5555, server: "localhost")
});
```

In order to handle events, the ```LinkEstablished```, ```LinkTerminated```, ```CommandHandler``` and ```QueryHandler``` event handlers can be bound:
```
netLinkServer.LinkEstablished += (link) => Console.WriteLine($"client->server link established: {link}");
netLinkServer.LinkTerminated += (link) => Console.WriteLine($"client->server link terminated: {link}");

netLinkServer.CommandHandler = async (INetLink link, NetMessage command, CancellationToken ct) =>
{
    Console.WriteLine($"Server Processing command: {command.GetCommand()}");
    await Task.Delay(100, ct); // some work here...
};

netLinkServer.QueryHandler = async (INetLink link, NetMessage query, CancellationToken ct) =>
{
    Console.WriteLine($"Server Processing query: {query.GetQuery()}");

    await Task.Delay(100, ct); // some work here...
    //string queryName = query.GetQuery();

    var resp = link.CreateResponse(query, true, "Server OK");
    return resp;
};
```

Then, all you need to do start handling connection is:
```
await netLinkServer.Run(ct); // Listen for incoming connections
```

Just like on the clients, the ```SendCommand()``` and ```SendQuery()``` methods can be used to send to a client link.

The list of active connections can be iterated through using the ```GetLinks()``` method, for broadcating.  For example:
```
foreach (var clientLink in netLinkServer.GetLinks())
{
    await clientLink.SendCommand(clientLink.CreateCommand("serverToClientCommand"), ct);

    var clientRepsonse = await clientLink.SendQuery(clientLink.CreateQuery("ServerToClientQuery").AddHeader("headerName", "headerValue"), ct);
    Console.WriteLine($"Client response: {clientRepsonse.GetResponse()}");
}
```

### Web Client Example

A browser can attach to a local WebSocket endpoint, as show in the following example.
See [NetlinkWebsocketTest.html](https://github.com/gitdonohue/NetLink/blob/develop/Examples/NetlinkWebsocketTest.html) (uses [Netlink.js](https://github.com/gitdonohue/NetLink/blob/develop/Examples/Netlink.js)).

<img width="995" alt="image" src="https://github.com/gitdonohue/NetLink/assets/44268295/4934f6e8-90d2-4584-9429-ea3bcd46db50">

Note: Encryption not supported, to be used on localhost or VPN/LAN only.

### C++ Client Example

See [NetLinkSocketClient.hpp](/NetLink/cpp/NetLinkSocketClient.hpp) / [NetLinkSocketClient.cpp](/NetLink/cpp/NetLinkSocketClient.cpp)

Example pending

## Encryption

In order to enable encrytion over the links, you have to install a certificate on the server. 
The default name for this certificate would be ```NetLinkServer```, but this name cand be changed by setting ```ServerCertificateName``` on the server. 
The server and client can check the ```IsEncrypted``` property and act accordingly.

If you want to validate the clients, you can also install a certificate on the client(s).
The default name for this certificate would be ```NetLinkClient```, but this name cand be changed by setting ```ClientCertificateName``` on the server. 
The server can then check the ```IsVerified``` flag on messages and act accordingly.  Warning: This has not been thoroughly tested.

To create a certificate which includes a private key:
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 900 -nodes
openssl pkcs12 -inkey key.pem -in cert.pem -export -out installable_cert.pfx
```
Or
https://certificatetools.com/

To disable encryption, you can set the ```AllowEncryption``` property to false on the server.

## Caveat Emptor

This package is meant to be a time-saver, easy to use, client-server library, for IPC or LAN use.  It is not meant as a robust, secure, highly scalable or performant system for a large number of connections.
It's used in production, but there are currently no unit tests to safeguard from regressions.  If anyone is interested in pursuing the idea of establishing a testing framework for this library, please feel free to contect me.
