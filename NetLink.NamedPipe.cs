using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using static NetLink.Utilities;

//Note: This is windows-only, unless NO_WINDOWS_NAMEDPIPES_ACL is defined.
//      But that would mean you could not connect different users (admin/non-admin).
//      See https://github.com/dotnet/runtime/issues/26400

namespace NetLink
{
    public sealed class NetLinkNamedPipe : NetLinkSharedBase, INetLink
    {
        public Guid Id => LinkGuid;

        public bool IsConnected => StreamIn?.IsConnected ?? false;
        public bool IsEncrypted => PublicKeyRsa != null;
        public bool IsVerified => false; // TODO

        public event EventHandler? OnConnected;
        public event EventHandler? OnDisconnected;

        private string ServerName { get; init; } = ".";
        private string ServerPipeName { get; init; } = "";

        private Guid LinkGuid { get; set; }

        public NetLinkNamedPipe(string server, string pipeName)
        {
            ServerName = server;
            ServerPipeName = pipeName;
            IsInitiator = true;
        }

        private PipeStream? StreamIn { get; set; }
        private PipeStream? StreamOut { get; set; }



        private CancellationTokenSource streamDisconnectedTokenSource = new CancellationTokenSource();

        internal NetLinkNamedPipe(PipeStream inStream, PipeStream outStream, Guid id)
        {
            StreamIn = inStream;
            StreamOut = outStream;
            LinkGuid = id;
        }

        public void Dispose()
        {

        }

        public async Task ConnectAndProcess(CancellationToken ct)
        {

            Trace($"connecting to {ServerPipeName}...");
            try
            {
                var guid_buffer = new byte[16];

                using (NamedPipeClientStream primaryPipeClient = new NamedPipeClientStream(ServerName, ServerPipeName, PipeDirection.In))
                {
                    // Connect to the pipe or wait until the pipe is available.
                    Trace($"Client Attempting to connect to primary pipe {ServerPipeName}...");
                    while (!ct.IsCancellationRequested)
                    {
                        try
                        {
                            //await primaryPipeClient.ConnectAsync(ct);
                            await primaryPipeClient.ConnectAsync(1000, ct);
                            break;
                        }
                        catch (TimeoutException)
                        {
                            continue;
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                    }

                    Trace("Client Connected to primary pipe.");

                    int c = await primaryPipeClient.ReadAsync(guid_buffer, ct);
                    if (c != 16)
                    {
                        throw new InvalidDataException("The pipe did not send a valid guid");
                    }

                    primaryPipeClient.Close();

                    var linkGuid = new Guid(guid_buffer);
                    LinkGuid = linkGuid;
                    string linkPipeName = $"{ServerPipeName}:{linkGuid}";

                    using (NamedPipeClientStream linkPipeClientIn = new NamedPipeClientStream(ServerName, linkPipeName + ":MOSI", PipeDirection.In))
                    using (NamedPipeClientStream linkPipeClientOut = new NamedPipeClientStream(ServerName, linkPipeName + ":MISO", PipeDirection.Out))
                    {
                        try
                        {
                            Trace($"Client Attempting to connect to link pipe {linkPipeName + ":MOSI"}...");
                            await linkPipeClientIn.ConnectAsync(ct);
                            Trace($"Client Attempting to connect to link pipe {linkPipeName + ":MISO"}...");
                            await linkPipeClientOut.ConnectAsync(ct);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            return;
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                        Trace("Client Connected to link pipe.");
                        //IsConnected = true;
                        //OnConnected?.Invoke(this, EventArgs.Empty);
                        _ = Task.Run(() => OnConnected?.Invoke(this, EventArgs.Empty));

                        StreamIn = linkPipeClientIn;
                        StreamOut = linkPipeClientOut;

                        await Listen(ct);

                        Trace("disconnected.");
                        //IsConnected = false;
                        //OnDisconnected?.Invoke(this, EventArgs.Empty);
                        _ = Task.Run(() => OnDisconnected?.Invoke(this, EventArgs.Empty));
                    }
                }
            }
            catch (TaskCanceledException)
            {
                Trace("connection attempt cancelled.");
                return;
            }
        }

        internal async Task Listen(CancellationToken ct)
        {
            if (StreamIn == null)
            {
                throw new InvalidOperationException("No pipe stream set.");
            }

            while (!ct.IsCancellationRequested && StreamIn.IsConnected)
            {
                byte[]? packet;
                try
                {
                    //Trace($"{Role} Waiting for ReceivePacket...");
                    packet = await ReceivePacket(StreamIn, ct);
                }
                catch (TaskCanceledException)
                {
                    continue;
                }
                catch (EndOfStreamException)
                {
                    continue;
                }

                if (packet != null && packet.Length > 0)
                {
                    NetMessage message = NetMessage.DeSerializeBinary(packet, this);    
                    _ = Task.Run(async () => await HandleMessageReception(message, ct));
                }
                else
                {
                    Trace($"{Role} Empty packet received.");
                    await Task.Delay(1000,ct); // to avoid spam
                }
            }

            Trace($"{Role} Read task stopped.");
        }

        SemaphoreSlim writeLock = new(1);

        private async Task WritePacket(Stream outputStream, ArraySegment<byte> data, CancellationToken ct)
        {
            //Trace($"{Role} Packet sending ({data.Count})...");
            using (await SemaphoreLock.AcquireLockAsync(writeLock, ct))
            {
                try
                {
                    await outputStream.WriteAsync(BitConverter.GetBytes(data.Count), ct);
                    await outputStream.WriteAsync(data, ct);
                }
                catch (IOException)
                {
                    Trace($"{Role} Stream write failed.");
                    return;
                }
            }
            //Trace($"{Role} Packet sent ({data.Count})");
        }

        private async Task<byte[]> ReceivePacket(PipeStream inputStream, CancellationToken ct)
        {
            MemoryStream ms = new();

            //Trace($"{Role} Packet waiting for read...");
            byte[] buffer = new byte[4];

            int readLength = await inputStream.ReadAsync(buffer, 0, 4, ct); // <- Cancellation token not honored!
            if (readLength == 0)
            {
                throw new EndOfStreamException("Peer disconnected");
            }

            int len = BitConverter.ToInt32(buffer, 0);
            //Trace($"{Role} Packet receiving ({len})...");
            buffer = new byte[len];
            int offset = 0;
            if (len == 0) throw new NotImplementedException();
            while (!ct.IsCancellationRequested && offset < len)
            {
                int readLen = await inputStream.ReadAsync(buffer, offset, len - offset, ct); // <- Cancellation token not honored!
                if (readLen == 0)
                {
                    throw new EndOfStreamException("Peer disconnected");
                }
                inputStream.Flush();
                ms.Write(buffer, offset, readLen);
                offset += readLen;
            }

            //Trace($"{Role} Packet received ({len})");
            return ms.ToArray();
        }

        //private SemaphoreSlim sendSemaphore = new SemaphoreSlim(1); // Websockets can only have one SendAsync in flight at any given time.

        internal async Task<bool> SendInternal(ArraySegment<byte> data, CancellationToken ct)
        {
            if (StreamOut != null)
            {
                //using (await SemaphoreLock.AcquireLockAsync(QuerySemaphore, ct))
                //using (await SemaphoreLock.AcquireLockAsync(sendSemaphore, ct, $"{Role} sendSemaphore"))
                {
                    await WritePacket(StreamOut, data, ct);
                    //await StreamOut.FlushAsync(ct);
                    return true;
                }
            }
            return false;
        }

        private byte[] SerializeMessage(NetMessage message) => message.SerializeBinary(this);

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
                    using (CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(streamDisconnectedTokenSource.Token, ct))
                    {
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
                        catch (InvalidOperationException e)
                        {
                            Trace($"{Role} InvalidOperationException: {e.Message}");
                            return INetLink.CreateResponse(query, false, "Invalid link state");
                        }
                    }
                }
                return INetLink.CreateResponse(query, false, "Not connected");
            }
        }
    }

    public sealed class NetLinkNamedPipeServer : INetLinkServer
    {
        public NetLinkNamedPipeServer(string pipeName = @"NetLink\NetLink_NP") { PipeName = pipeName; }
        private string PipeName { get; init; }

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
        public IEnumerable<INetLink> GetLinks() => ActiveLinks;

        private NamedPipeServerStream CreatePipeServerStream(string pipeName, PipeDirection direction, 
            int maxNumberOfServerInstances = NamedPipeServerStream.MaxAllowedServerInstances, 
            PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte, 
            PipeOptions options = PipeOptions.None)
        {
#if NO_WINDOWS_NAMEDPIPES_ACL
            return new NamedPipeServerStream(pipeName, direction, maxNumberOfServerInstances, transmissionMode, options);
#else
#pragma warning disable CA1416 // Validate platform compatibility
            //
            // Windows-only. This is required if a non-admin process should be allowed to connect to an admin pipe.
            //
            // See https://github.com/dotnet/runtime/issues/26400
            PipeSecurity pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
            return NamedPipeServerStreamAcl.Create(pipeName, direction, maxNumberOfServerInstances, transmissionMode, options, 0, 0, pipeSecurity);
#pragma warning restore CA1416 // Validate platform compatibility
#endif
        }

        public async Task Run(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                using (var pipeServer = CreatePipeServerStream(PipeName, PipeDirection.Out, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                {
                    Trace($"Server Waiting for client connection on named pipe: {PipeName}...");
                    try
                    {
                        await pipeServer.WaitForConnectionAsync(ct);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    Trace("Server received client connection.");

                    // Create a new pipe for this client link
                    Guid link_guid = Guid.NewGuid();
                    string linkPipeName = $"{PipeName}:{link_guid}";
                
                    NamedPipeServerStream linkPipeOutgoing = CreatePipeServerStream(linkPipeName + ":MOSI", PipeDirection.Out);
                    NamedPipeServerStream linkPipeIncomming = CreatePipeServerStream(linkPipeName + ":MISO", PipeDirection.In);

                    // Send new link guid to client on primary pipe
                    await pipeServer.WriteAsync(link_guid.ToByteArray(), ct);

                    var linkListenTask = async () =>            
                    {
                        try
                        {
                            // Wait for client to connect on new pipe
                            Trace($"Server Waiting for client connection to link named pipe: {linkPipeName}...");
                            try
                            {
                                await linkPipeOutgoing.WaitForConnectionAsync(ct);
                                await linkPipeIncomming.WaitForConnectionAsync(ct);
                            }
                            catch (IOException)
                            {
                                return;
                            }
                            Trace("Server received client connection to link pipe.");

                            var link = new NetLinkNamedPipe(linkPipeIncomming, linkPipeOutgoing, link_guid) { AllowCompression = this.AllowOutgoingCompression, AllowEncryption = this.AllowEncryption };
                            ActiveLinks.Add(link);

                            await link.InternalOnLinkEstablished(ct);

                            link.CommandHandler = this.CommandHandler;
                            link.QueryHandler = this.QueryHandler;
                            LinkEstablished?.Invoke(link);

                            await link.Listen(ct);

                            ActiveLinks.Remove(link);
                            LinkTerminated?.Invoke(link);
                        }
                        finally
                        {
                            linkPipeOutgoing.Dispose();
                            linkPipeIncomming.Dispose();
                        }

                    };
            
                    //await linkListenTask();    
                    await Task.Factory.StartNew(() => linkListenTask(), creationOptions: TaskCreationOptions.AttachedToParent);
                }
            }
        }
    }
}
