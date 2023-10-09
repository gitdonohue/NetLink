# NetLink

NetLink Client-Server Helper Library for .Net/C#.

## Description

A helper library to establish client-server links of over different transports (tcp-sockets/named-pipes/web-sockets/...).

NetLink is a simple way to establish a network link between a server and client(s), and have commands and queries be sent asynchronously between both.
This can be used for simple IPC, or to manage remote connections.

## Features

- Simple integration
- Connection-based link
- Commands and Queries
- Strings, headers and byte array payloads
- Works over TCP Sockets, WebSockets or Named Pipes
- Encryption (X509Certificates certificate-based)
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

To handle client events, CommandHandler and QueryHandler event handlers can be bound, just like in the server.  OnConnected and OnDisconnected can also be bound for connection events.
Just like on the server, the ```SendCommand()``` and ```SendQuery()``` methods can be used to send to the server.

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

The list of active connections can be iterated through using the ```GetLinks()``` method, for broadcating, for example.

Just like on the clients, the ```SendCommand()``` and ```SendQuery()``` methods can be used to send to a client link.

In order to send commands to clients, links have a ```SendCommand()``` method:
```
await clientLink.SendCommand(clientLink.CreateCommand("serverToClientCommand"), ct);
```

To query clients, the ```SendQuery()``` can be used:
```
var clientRepsonse = await clientLink.SendQuery(clientLink.CreateQuery("ServerToClientQuery").AddHeader("headerName", "headerValue"), ct);
Console.WriteLine($"Client response: {clientRepsonse.GetResponse()}");
```

## Caveat Emptor

This package is meant to be a time-savor, easy to use, client-server library.  It is not meant as a robust, secure, highly scalable or performant system for a large number of connections.
It's used in production, but there are currently no unit tests to safeguard from regressions.  If anyone is interested in pursuing the idea of establishing a testing framework for this library, please feel free to contect me.
