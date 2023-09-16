// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.WebSockets;
using static NetLink.Utilities;

namespace NetLink;

public sealed class NetLinkWebsocket : NetLinkSharedBase, INetLink
{
    public Guid Id => LinkGuid;

    public bool IsConnected => websocket?.State == WebSocketState.Open;
    public bool IsEncrypted => PublicKeyRsa != null;
    public bool IsVerified => false; // TODO

    public event EventHandler? OnConnected;
    public event EventHandler? OnDisconnected;

    private string ServerName { get; init; } = string.Empty;
    private int ServerPort { get; init; }

    private WebSocket? websocket;
    private readonly CancellationTokenSource websocketDisconnectedTokenSource = new();

    private Guid LinkGuid { get; set; }

    public enum EncodingType { Binary, Text };
    internal EncodingType Encoding { get; init; } = EncodingType.Binary;

		IReadOnlyDictionary<string, string> INetLink.Properties => Properties;

		internal NetLinkWebsocket(WebSocket ws, Guid id, EncodingType encoding)
    {
        websocket = ws;
        LinkGuid = id;
        Encoding = encoding;
        //OnConnected?.Invoke(this, EventArgs.Empty);
        _ = Task.Run(() => OnConnected?.Invoke(this, EventArgs.Empty));
    }

    public NetLinkWebsocket(string server, int port, EncodingType encoding)
    {
        ServerName = server;
        ServerPort = port;
        Encoding = encoding;
    }

    public async Task ConnectAndProcess(CancellationToken ct)
    {
        ResetAtConnection();

        ClientWebSocket clientWebSocket = new();
        websocket = clientWebSocket;

        // Force text encoding.
        if (Encoding == EncodingType.Text)
        {
            clientWebSocket.Options.SetRequestHeader("User-Agent", "Json");
        }

        string servername = (ServerName == "localhost") ? ServerName : GetServerAddress(ServerName).ToString();
        Uri uri = new($"ws://{servername}:{ServerPort}/");

        Trace($"connecting to {uri}...");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                CancellationTokenSource tcts = new();
                tcts.CancelAfter(2000);
                using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(tcts.Token, ct);
                try
                {
                    await clientWebSocket.ConnectAsync(uri, linkedCts.Token);
                    break;
                }
                catch (WebSocketException e)
                {
                    throw new Exception($"Error connecting to websocket: {e.Message}");
                }
                catch (TaskCanceledException e)
                {
                    if (ct.IsCancellationRequested) throw e;
                    clientWebSocket.Abort();
                    clientWebSocket = new();
                    websocket = clientWebSocket;
                }
            }

            // First 16 bytes received from the server are the link guid
            var receiveBuffer = new byte[512];
            WebSocketReceiveResult result = await clientWebSocket.ReceiveAsync(receiveBuffer, ct);
            if (result.MessageType == WebSocketMessageType.Binary && result.Count == 16)
            {
                LinkGuid = new Guid(new ArraySegment<byte>(receiveBuffer, 0, 16));
            }
            else if (result.MessageType == WebSocketMessageType.Text && result.Count > 0)
            {
                LinkGuid = new Guid(System.Text.Encoding.UTF8.GetString(new ArraySegment<byte>(receiveBuffer, 0, result.Count)));
            }
            else
            {
                Trace("connection attempt failed, invalid data received from server.");
                return;
            }
        }
        catch (TaskCanceledException)
        {
            Trace("connection attempt cancelled.");
            return;
        }
        
        Trace("connected.");
        //OnConnected?.Invoke(this, EventArgs.Empty);
        _ = Task.Run(() => OnConnected?.Invoke(this, EventArgs.Empty));

        await Listen(ct);

        Trace("disconnected.");
        //OnDisconnected?.Invoke(this, EventArgs.Empty);
        _ = Task.Run(() => OnDisconnected?.Invoke(this, EventArgs.Empty));
    }

    internal async Task Listen(CancellationToken ct)
    {
        var receiveBuffer = new byte[4096];
        while (!ct.IsCancellationRequested)
        {
            if (!IsConnected)
            {
                Trace("Socket not connected.");
                break;
            }

            if (websocket == null) throw new InvalidOperationException();

            WebSocketReceiveResult? result;
            try
            {
                result = await websocket.ReceiveAsync(receiveBuffer, ct);
            }
            catch (WebSocketException e)
            {
                Trace($"Listening stopped: {e.Message}");
                return;
            }
            catch (Exception e) when (e is OperationCanceledException || e is TaskCanceledException)
            {    
                Trace("Listening cancelled.");
                return;
            }
            if (result == null) return;

            if (result.MessageType == WebSocketMessageType.Close)
            {
                Trace("Close message received.");
                await websocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, ct);
                break;
            }
            else if (result.Count > 0)
            {
                var messageData = new ArraySegment<byte>(receiveBuffer, 0, result.Count);
                NetMessage message = DeSerialize(messageData, result.MessageType);
                _ = Task.Run(async () => await HandleMessageReception(message, ct));
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }

    public void Dispose()
    {
        websocket?.Dispose();
        websocket = null;
    }

    private readonly SemaphoreSlim sendSemaphore = new(1); // Websockets can only have one SendAsync in flight at any given time.

    internal async Task<bool> SendInternal(ArraySegment<byte> data, CancellationToken ct)
    {
        if (websocket != null)
        {
            using (await SemaphoreLock.AcquireLockAsync(sendSemaphore, ct))
            {
                WebSocketMessageType messageType = (Encoding == EncodingType.Binary) ? WebSocketMessageType.Binary : WebSocketMessageType.Text;
                await websocket.SendAsync(data, messageType, messageFlags: WebSocketMessageFlags.EndOfMessage, ct);
                return true;
            }
        }
        return false;
    }

    internal async Task<bool> SendInternal(Guid guid, CancellationToken ct)
    {
        if (Encoding == EncodingType.Text)
        {
            return await SendInternal(System.Text.Encoding.UTF8.GetBytes(guid.ToString()), ct);
        }
        else
        {
            return await SendInternal(guid.ToByteArray(), ct);
        }
    }

    private byte[] SerializeMessage(NetMessage message)
    {
        switch (Encoding)
        {
            case EncodingType.Text: return message.SerializeText(this);
            default: return message.SerializeBinary(this);
        }
    }

    private NetMessage DeSerialize(ArraySegment<byte> data, WebSocketMessageType type)
    {
        try
        {
            return (type == WebSocketMessageType.Text) ?
                NetMessage.DeSerializeText(data, this)
                : NetMessage.DeSerializeBinary(data, this);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Data not deserializable to NetMessage: {ex.Message}");
        }
    }

    protected override async Task<bool> SendMessageImpl(NetMessage command, CancellationToken ct)
    {
        if (IsConnected)
        {
            return await SendInternal(SerializeMessage(command), ct);
        }
        return false;
    }

    public async Task<bool> SendCommand(NetMessage command, CancellationToken ct) => await SendMessage(command, ct);

    public async Task<NetMessage> SendQuery(NetMessage query, CancellationToken ct)
    {
        Trace($"{Role} Sending query: {query}");
        if (IsConnected)
        {
            using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(websocketDisconnectedTokenSource.Token, ct);
            try
            {
                if (!await SendInternal(SerializeMessage(query), linkedCts.Token))
                {
                    return INetLink.CreateResponse(query, false, "Request failed");
                }
                return await WaitResponse(query, linkedCts.Token);
            }
            catch (OperationCanceledException)
            {
                return INetLink.CreateResponse(query, false, "Cancelled");
            }
            catch (InvalidOperationException)
            {
                return INetLink.CreateResponse(query, false, "Invalid link state");
            }
        }
        return INetLink.CreateResponse(query, false, "Not connected");
    }
}

public sealed class NetLinkWebsocketServer : INetLinkServer
{
    public NetLinkWebsocketServer(int port, string server = "auto") 
    { 
        Port = port;
        ServerName = server;
    }

    public bool AllowEncryption { get; init; } = true;
    public bool AllowOutgoingCompression { get; init; } = true;

    public event Action<INetLink>? LinkEstablished;
    public event Action<INetLink>? LinkTerminated;
    public Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler { get; set; }
    public Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler { get; set; }

    public string ServerName { get; init; }
    private int Port { get; init; }

    private HttpListener? httpListener;
    private HashSet<INetLink> ActiveLinks { get; set; } = new();
    public IEnumerable<INetLink> GetLinks() => ActiveLinks;

    private bool Verbose => INetLink.Verbose;

    public void Dispose()
    {
        httpListener?.Close();
        httpListener = null;
    }

    public async Task Run(CancellationToken ct)
    {
        //Trace($"Websocket server starting on {Address}...");
        httpListener = new();

        string serverName = ServerName;
        if (serverName == "auto")
        {
            serverName = GetServerAddress(ServerName).ToString();
        }

        string address = $"{serverName}:{Port}";
        httpListener.Prefixes.Add($"http://{address}/");
        try
        {
            httpListener.Start();
        }
        catch (HttpListenerException e)
        {
            Trace($"Could not start websocket server on {address}: {e.Message}");
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            // Wait for connection
            Trace($"Server waiting for client connection on websocket: {ServerName} ({address})...");
            HttpListenerContext? context = await httpListener.GetContextAsync().WithCancellationToken(ct);
            if (context is null) return;

            var linkListenTask = async () =>
            {
                Trace($"Client connected from : {context.Request.UserHostName} ({context.Request.RemoteEndPoint})");

                if (context.Request.IsWebSocketRequest)
                {
                    HttpListenerWebSocketContext? webSocketContext =
                        await context.AcceptWebSocketAsync(subProtocol: null).WithCancellationToken(ct);

                    if (webSocketContext is null) throw new InvalidOperationException("webSocketContext error");

                    byte[] socketKey = Convert.FromBase64String(webSocketContext.SecWebSocketKey);
                    Guid socketGuid = new Guid(socketKey);

                    NetLinkWebsocket.EncodingType encoding = NetLinkWebsocket.EncodingType.Binary;

                    bool useTextEncoding = webSocketContext.Headers.AllKeys.Contains("User-Agent");
                    if (useTextEncoding)
                    {
                        encoding = NetLinkWebsocket.EncodingType.Text;
                    }

                    WebSocket webSocket = webSocketContext.WebSocket;
                    var link = new NetLinkWebsocket(webSocket, socketGuid, encoding) { AllowCompression = this.AllowOutgoingCompression, AllowEncryption = this.AllowEncryption };
                    ActiveLinks.Add(link);

                    // Send the link guid to the connecting client
                    await link.SendInternal(socketGuid, ct);

                    await link.InternalOnLinkEstablished(ct);

                    link.CommandHandler = this.CommandHandler;
                    link.QueryHandler = this.QueryHandler;
                    LinkEstablished?.Invoke(link);

                    await link.Listen(ct);
                    ActiveLinks.Remove(link);
                    LinkTerminated?.Invoke(link);
                }
                else
                {
                    Trace($"Error: not a websocket request.");
                    context.Response.Abort();
                }
            };
            
            await Task.Factory.StartNew(() => linkListenTask(), creationOptions: TaskCreationOptions.AttachedToParent);
        }
    }
}
