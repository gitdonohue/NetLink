// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using static NetLink.Utilities;

namespace NetLink;

public sealed class NetLinkSocket : NetLinkSharedBase, INetLink
{
    public string TransportName => "Socket";
    public bool TransportHandlesEncryption => false;

    public Guid Id => LinkGuid;

    public bool IsConnected => NetworkStream?.Socket.Connected ?? false;
    public bool IsEncrypted => PublicKeyRsa != null;
    public bool IsVerified => false; // TODO

	IReadOnlyDictionary<string, string> INetLink.Properties => Properties;

	public event EventHandler? OnConnected;
    public event EventHandler? OnDisconnected;

    private string ServerName { get; init; } = "localHost";
    private int ServerPort { get; init; } = -1;

    private Guid LinkGuid { get; set; }

    public NetLinkSocket(string server, int port, X509Certificate2? certificate = null)
        : base(certificate)
    {
        ServerName = server;
        ServerPort = port;
        IsInitiator = true;
    }

    private NetworkStream? NetworkStream { get; set; }

    private readonly CancellationTokenSource streamDisconnectedTokenSource = new();

    internal NetLinkSocket(NetworkStream stream, Guid id, X509Certificate2? certificate)
        : base(certificate)
    {
        NetworkStream = stream;
        LinkGuid = id;
    }

    public void Dispose()
    {
        NetworkStream?.Close();
        NetworkStream = null;
    }

    public override string ToString() => Id.ToString();

    private void CloseStream()
    {
        NetworkStream?.Close();
        NetworkStream = null;
    }

	public async Task ConnectAndProcess(CancellationToken ct)
    {
        ResetAtConnection();

        //Trace($"connecting to {ServerName}:{ServerPort}...");
        try
        {
            var guid_buffer = new byte[16];

            IPEndPoint endPoint = new IPEndPoint(GetServerAddress(ServerName), ServerPort);
            Trace($"connecting to {ServerName}({endPoint})...");

            Socket clientSocket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            while (!ct.IsCancellationRequested)
            {
                CancellationTokenSource tcts = new();
                tcts.CancelAfter(2000);
                using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(tcts.Token, ct);
                try
                {
                    await clientSocket.ConnectAsync(endPoint, linkedCts.Token);
                    break;
                }
                catch (TaskCanceledException)
                {
                    if (ct.IsCancellationRequested) throw;
                }
                catch (OperationCanceledException)
                {
                    // Try again...
                    clientSocket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                }
            }

            Trace($"Server sending session GUID...");
            int rCount = await clientSocket.ReceiveAsync(guid_buffer, SocketFlags.None, ct);

            if (rCount != 16) throw new InvalidDataException("The server did not send a valid guid");

            var linkGuid = new Guid(guid_buffer);
            LinkGuid = linkGuid;

            //OnConnected?.Invoke(this, EventArgs.Empty);
            _ = Task.Run(() => OnConnected?.Invoke(this, EventArgs.Empty));

            var clientStream = new NetworkStream(clientSocket);

            NetworkStream = clientStream;

            try
            {
                await Listen(ct);
            }
            catch (Exception e)
            {
                Trace($"Link listener error: {e.Message}");
                //throw;
            }

            Trace("disconnected.");
            //OnDisconnected?.Invoke(this, EventArgs.Empty);
            _ = Task.Run(() => OnDisconnected?.Invoke(this, EventArgs.Empty));
        }
        catch (TaskCanceledException)
        {
            Trace("connection attempt cancelled.");
            return;
        }
    }

    internal async Task Listen(CancellationToken ct)
    {
        if (NetworkStream == null) throw new InvalidOperationException("No input stream set.");

        while (!ct.IsCancellationRequested && IsConnected)
        {
            byte[]? packet;
            try
            {
                //Trace($"{Role} Waiting for ReceivePacket...");
                packet = await ReceivePacket(NetworkStream, ct);
            }
            catch (TaskCanceledException)
            {
                CloseStream();
                continue;
            }
            catch (EndOfStreamException)
            {
                CloseStream();
                continue;
            }

            if (packet != null && packet.Length > 0)
            {
                NetMessage message = NetMessage.InternalDeSerializeBinary(packet, this);
                _ = Task.Run(async () => await HandleMessageReception(message, ct));
            }
            else
            {
                Trace($"{Role} Empty packet received.");
                await Task.Delay(1000, ct); // to avoid spam
            }
        }

        Trace($"{Role} Read task stopped.");
    }

    //SemaphoreSlim writeLock = new(1);

    private async Task<bool> WritePacket(Stream outputStream, ArraySegment<byte> data, CancellationToken ct)
    {
        //Trace($"{Role} Packet sending ({data.Count})...");
        //using (await SemaphoreLock.AcquireLockAsync(writeLock, ct))
        {
            try
            {
                await outputStream.WriteAsync(BitConverter.GetBytes(data.Count), ct);
                await outputStream.WriteAsync(data, ct);
                Trace($"{Role} Packet sent ({data.Count})");
                return true;
            }
            catch (IOException)
            {
                Trace($"{Role} Stream write failed.");
                CloseStream();
                return false;
            }
        }
    }

    private async Task<byte[]> ReceivePacket(Stream inputStream, CancellationToken ct)
    {
        MemoryStream ms = new();

        //Trace($"{Role} Packet waiting for read...");

        try
        {
            byte[] buffer = new byte[4];
            int readLength = await inputStream.ReadAsync(buffer, 0, 4, ct);
            if (readLength == 0) throw new EndOfStreamException("Peer disconnected");

            int len = BitConverter.ToInt32(buffer, 0);
            buffer = new byte[len];
            //Trace($"{Role} Packet receiving ({len})...");
            int offset = 0;
            if (len == 0) throw new NotImplementedException();
            while (!ct.IsCancellationRequested && offset < len)
            {
                int readLen = await inputStream.ReadAsync(buffer, offset, len - offset, ct);
                if (readLen == 0) throw new EndOfStreamException("Peer disconnected");

                inputStream.Flush();
                ms.Write(buffer, offset, readLen);
                offset += readLen;
            }
        }
        catch (OperationCanceledException)
        {
            throw new EndOfStreamException("Peer disconnected");
        }
        //Trace($"{Role} Packet received ({len})");
        return ms.ToArray();
    }

    //private SemaphoreSlim sendSemaphore = new SemaphoreSlim(1); // Websockets can only have one SendAsync in flight at any given time.

    internal async Task<bool> SendInternal(ArraySegment<byte> data, CancellationToken ct)
    {
        if (NetworkStream != null)
        {
            //using (await SemaphoreLock.AcquireLockAsync(QuerySemaphore, ct))
            //using (await SemaphoreLock.AcquireLockAsync(sendSemaphore, ct, $"{Role} sendSemaphore"))
            {
                return await WritePacket(NetworkStream, data, ct);
            }
        }
        return false;
    }

    private byte[] SerializeMessage(NetMessage message) => message.InternalSerializeBinary(this);

    protected override async Task<bool> SendMessageImpl(NetMessage message, CancellationToken ct)
    {
        if (IsConnected)
        {
            return await SendInternal(SerializeMessage(message), ct);
        }
        return false;
    }

    public async Task<bool> SendCommand(NetMessage command, CancellationToken ct) => await SendMessage(command, ct);

    public async Task<NetMessage> SendQuery(NetMessage query, CancellationToken ct)
    {
        Trace($"{Role} Sending query: {query}");
        //using (await SemaphoreLock.AcquireLockAsync(QuerySemaphore, ct))
        {
            if (IsConnected)
            {
                using CancellationTokenSource linkedCts =
                    CancellationTokenSource.CreateLinkedTokenSource(streamDisconnectedTokenSource.Token, ct);
                using SemaphoreSlim requestSemaphore = new(0);
                // Register the semaphore BEFORE sending the query
                if (!PendingRequests.TryAdd(query.QueryId, requestSemaphore))
                {
                    return INetLink.CreateResponse(query, false, "Duplicate QueryId");
                }

                try
                {
                    if (!await SendInternal(SerializeMessage(query), linkedCts.Token))
                    {
                        PendingRequests.TryRemove(query.QueryId, out _); // Clean up
                        return INetLink.CreateResponse(query, false, "Request failed");
                    }

                    Trace($"{Role} Query sent, waiting for response: {query}");
                    await requestSemaphore.WaitAsync(linkedCts.Token);
                    return WaitResponse(query, linkedCts.Token);
                }
                catch (OperationCanceledException)
                {
                    PendingRequests.TryRemove(query.QueryId, out _); // Clean up
                    return INetLink.CreateResponse(query, false, "Cancelled");
                }
                catch (InvalidOperationException e)
                {
                    PendingRequests.TryRemove(query.QueryId, out _); // Clean up
                    Trace($"{Role} InvalidOperationException: {e.Message}");
                    return INetLink.CreateResponse(query, false, "Invalid link state");
                }
            }
            return INetLink.CreateResponse(query, false, "Not connected");
        }
    }
}

public sealed class NetLinkSocketServer : INetLinkServer
{
    public NetLinkSocketServer(int port, string server = "auto") 
    { 
        Port = port; 
        Server = server;
        Endpoint = new IPEndPoint(GetServerAddress(server), Port);
    }
    
    public string Server { get; init; }
    private int Port { get; init; }
    private IPEndPoint? Endpoint { get; init; }

    public System.Security.Cryptography.X509Certificates.X509Certificate2? Certificate { get; init; } = null;
    public bool AllowEncryption { get; init; } = true;
    public bool AllowOutgoingCompression { get; init; } = true;

    public event Action<INetLink>? LinkEstablished;
    public event Action<INetLink>? LinkTerminated;
    public Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler { get; set; }
    public Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler { get; set; }

    public void Dispose()
    {
    }

    private HashSet<INetLink> ActiveLinks { get; set; } = new();
    public IEnumerable<INetLink> GetLinks() => ActiveLinks.ToList(); // Copy so that new links can be created while iterating

    public async Task Run(CancellationToken ct)
    {
        var serverSocket = new TcpListener(Endpoint!);
        serverSocket.Start();

        while (!ct.IsCancellationRequested)
        {
            Trace($"Server Waiting for client connection on socket: {Server} ({Endpoint})...");

            TcpClient? client;
            try
            {
                client = await serverSocket.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
                
            if (client == null)
            {
                Trace("Server terminated.");
                return;
            }
                
            Trace("Server received client connection.");

            // Create a new pipe for this client link
            Guid link_guid = Guid.NewGuid();
                
            NetworkStream clientStream = client.GetStream();

            // Send new link guid to client on primary pipe
            await clientStream.WriteAsync(link_guid.ToByteArray(), ct);

            var linkListenTask = async () =>
            {
                try
                {
					NetLinkSocket link = new NetLinkSocket(clientStream, link_guid, Certificate) { AllowCompression = this.AllowOutgoingCompression, AllowEncryption = this.AllowEncryption };
                    string remote = client.Client.RemoteEndPoint?.ToString() ?? string.Empty;
                    link.SetProperty("remote", remote);
						ActiveLinks.Add(link);

                    await link.InternalOnLinkEstablished(ct);

                    link.CommandHandler = this.CommandHandler;
                    link.QueryHandler = this.QueryHandler;
                    LinkEstablished?.Invoke(link);

                    try
                    {
                        await link.Listen(ct);
                    }
                    catch (Exception e)
                    {
                        Trace($"Link listener error: {e.Message}");
                        //throw;
                    }

                    ActiveLinks.Remove(link);
                    LinkTerminated?.Invoke(link);
                }
                finally
                {
                    //linkPipeOutgoing.Dispose();
                    //linkPipeIncomming.Dispose();
                    //clientStream.Dispose();
                    client.Dispose();
                }
            };

            //await linkListenTask();    
            await Task.Factory.StartNew(() => linkListenTask(), creationOptions: TaskCreationOptions.AttachedToParent);
        }
    }
}
