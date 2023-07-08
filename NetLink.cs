namespace NetLink
{
    //
    // An abstraction for a client to server network link.
    // Links are full duplex and support asynchronous commands and requests.
    // In the OSI model, this would sit between the Presentation(6) and Application(7) layers.
    //
    // Supports link-level compression.
    // Supports link-level encryption and/or validation using X509 certificates (not in Text mode, obviously).
    //
    // Supported transports:
    // - Sockets
    // - Windows Named Pipes
    // - Websockets (binary and text)
    //
    //
    // To create a certificate which includes a private key:
    // openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 900 -nodes
    // openssl pkcs12 -inkey key.pem -in cert.pem -export -out installable_cert.pfx
    // Or
    // https://certificatetools.com/
    //
    // Note:
    // On Windows, if you get a "Could not start websocket server on xxxx:yyyy: Access is denied.", you can either run as administrator or run the following:
    // netsh http add urlacl url=http://xxxx:yyyy/ user=YOUR_DOMAIN\YourUserName
    //

    //
    // TODO:
    // - Use AES encryption, client generates key and sends it encrypted with RSA.  Use Query/Session ID as IV vectors.
    // - Implement Plain Sockets
    // - Implement Client+Server certificate validation (?)

    public interface INetLink : IDisposable
    {
        Guid Id { get; }
        bool IsConnected { get; }
        IReadOnlyDictionary<string, string> Properties { get; }

        event EventHandler? OnConnected;
        event EventHandler? OnDisconnected;
        Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler { set; }
        Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler { set; }

        Task ConnectAndProcess(CancellationToken ct);
        Task<bool> SendCommand(NetMessage command, CancellationToken ct);
        Task<NetMessage> SendQuery(NetMessage query, CancellationToken ct);

        public static bool Verbose { get; set; }

        public NetMessage CreateCommand(string command = "") => new NetMessage(this, "command", command);
        public NetMessage CreateQuery(string query = "") => new NetMessage(this, "query", query) { QueryId = Guid.NewGuid() };
        public NetMessage CreateResponse(NetMessage query, bool valid, string response) => new NetMessage(this, "response", response) { QueryId = query.QueryId, IsQueryResponse = true, IsValid = valid };
    }

    public interface INetLinkServer : IDisposable
    {
        bool AllowEncryption { init; }
        bool AllowOutgoingCompression { init; }

        event Action<INetLink>? LinkEstablished;
        event Action<INetLink>? LinkTerminated;

        Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler { set; }
        Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler { set; }

        IEnumerable<INetLink> GetLinks();

        Task Run(CancellationToken ct);

        public static string ServerCertificateName { get; set; } = "NetLinkServer";
        public static string ClientCertificateName { get; set; } = "NetLinkClient";
    }

    public sealed partial class NetMessage
    {
        public Dictionary<string,string> Headers { get; set; } = new();
        public byte[] Data { get; set; } = {};
        public Guid QueryId { get; set; } = Guid.Empty;
        public bool IsQueryResponse { get; internal set; } = false;
        public bool IsValid { get; set; } = true; // Q: Scrap this?
        public bool IsEncrypted { get; internal set; }
        public bool IsVerified { get; internal set; }
        public INetLink Link { get; init; }

        public string GetHeader(string key) => Headers.TryGetValue(key, out string? header) ? header : string.Empty;
        public string GetCommand() => GetHeader("command");
        public string GetQuery() => GetHeader("query");
        public string GetResponse() => GetHeader("response");
        public NetMessage AddHeader(string key, string value) { this.Headers[key] = value; return this; }

        public static int MaxToStringLen { get; set; } = 512;
    }
}
