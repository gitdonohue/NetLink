// SPDX-License-Identifier: MIT

using NetLink;

//
// To create a certificate which includes a private key:
// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 900 -nodes
// openssl pkcs12 -inkey key.pem -in cert.pem -export -out installable_cert.pfx
// Or
// https://certificatetools.com/
//


Console.WriteLine("Starting NetLink example application.");
CancellationTokenSource cts = new();
var ct = cts.Token;

#region Server Code

//
// Server example
//

// Single endpoint
//var netLinkServer = new NetLinkSocketServer(port: 4444, server: "auto");

// Multiple endpoints
var netLinkServer = new NetLinkAggregateServer(new List<INetLinkServer>()
{
    new NetLinkSocketServer(port: 4444, server: "auto"),
    new NetLinkSocketServer(port: 4445, server: "localhost") { AllowEncryption = false },
    new NetLinkSocketServer(port: 4446, server: "127.0.0.1") { AllowEncryption = false },
    new NetLinkNamedPipeServer(pipeName: @"Netlink\NetlinkNamedPipeServerExample"),
    new NetLinkWebsocketServer(port: 5555, server: "localhost")
});

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

#endregion Server Code


#region Client Code
//
// Client example
//

INetLink netlinkCLient = new NetLinkSocket(server: "localhost", port: 4445);
//INetLink netlinkCLient = new NetLinkNamedPipe(server: "localhost", pipeName: @"Netlink\NetlinkNamedPipeServerExample");
//INetLink netlinkCLient = new NetLinkWebsocket(server: "localhost", port: 5555, NetLinkWebsocket.EncodingType.Text);

netlinkCLient.OnConnected += (_, _) => Console.WriteLine($"Client Link established: {netlinkCLient.Id}");
netlinkCLient.OnDisconnected += (_, _) => Console.WriteLine($"Client Link disconnected: {netlinkCLient.Id}");

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

#endregion Client Code

//
// Messages examples
//

var messagesExamplesTask = async () =>
{
    await Task.Delay(2000, ct);
    Console.WriteLine("Staring messages examples...");

    while (!ct.IsCancellationRequested)
    {
        // client -> server
        if (netlinkCLient.IsConnected)
        {
            // client -> server command
            await netlinkCLient.SendCommand(netlinkCLient.CreateCommand("clientToServerCommand"), ct);

            await Task.Delay(1000, ct);

            // client -> server query
            var serverResponse = await netlinkCLient.SendQuery(netlinkCLient.CreateQuery("clientToServerQuery").AddHeader("headerName","headerValue"), ct);
            Console.WriteLine($"Server response: {serverResponse.GetResponse()}");
        }

        // server -> clients
        foreach (var clientLink in netLinkServer.GetLinks())
        {
            await Task.Delay(1000, ct);
            await clientLink.SendCommand(clientLink.CreateCommand("serverToClientCommand"), ct);

            await Task.Delay(1000, ct);
            var clientRepsonse = await clientLink.SendQuery(clientLink.CreateQuery("ServerToClientQuery").AddHeader("headerName", "headerValue"), ct);
            Console.WriteLine($"Client response: {clientRepsonse.GetResponse()}");
        }

        await Task.Delay(1000, ct);
    }
    Console.WriteLine("Messages examples cancelled.");
};

//
// Run client and server tasks
//

INetLink.Verbose = true;

Console.CancelKeyPress += (_, _) =>
{
    Console.WriteLine("Stopping services...");
    cts.Cancel();
};
Console.WriteLine("Press CTRL+C to cancel.");

var serverRunTask = async () => await netLinkServer.Run(ct); // Listen for incoming connections

var clientConnectTask = async () =>
{
    await Task.Delay(1000, ct); // Give a little time for server startup
    await netlinkCLient.ConnectAndProcess(ct);
};

List<Task> tasksToRun = new() { serverRunTask(), clientConnectTask(), messagesExamplesTask() };
try
{
    // Run all task in parrallel, until completion or cancellation
    await Task.WhenAll(tasksToRun);
}
catch (TaskCanceledException)
{
    Console.WriteLine("Server loop cancelled");
}
