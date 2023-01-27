using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace NetLink
{
    // Internal implementation for NetMessage
    public sealed partial class NetMessage
    {
        public override string ToString()
        {
            string jsonText = System.Text.Json.JsonSerializer.Serialize(this);

            // Replace passwords in logs
            var r = @"""password""\s{0,}\:\s{0,}""(?<password>[^""]+)""";
            jsonText = Regex.Replace(jsonText, r, "\"??????\"");

            if (jsonText.Length > MaxToStringLen) jsonText = jsonText.Substring(0, MaxToStringLen) + "...";

            return jsonText;
        }

        internal NetMessage(INetLink link) { Link = link; }
        internal NetMessage(INetLink link, string key, string val) { Link = link; Headers.Add(key, val); }

        [Flags] internal enum MessageFlags { None=0, Compressed=1, Signed=2, EncryptedRsa=4, EncryptedAes=8 }

        internal byte[] SerializeText(INetLink link)
        {
            //return System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(this));

            var dict = new Dictionary<string, string>();
            dict.Add("Headers", System.Text.Json.JsonSerializer.Serialize(this.Headers));
            if (Data.Length > 0) dict.Add("Data", Convert.ToBase64String(Data));
            if (QueryId != Guid.Empty) dict.Add("QueryId", QueryId.ToString());
            return System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(dict));
        }

        internal static NetMessage DeSerializeText(ArraySegment<byte> data, INetLink link)
        {
            var msg = new NetMessage(link);

            string txt = System.Text.Encoding.UTF8.GetString(data);

            var jsonDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(txt);
            if (jsonDict == null) throw new InvalidDataException($"Json data malformed: {txt}");

            if (jsonDict.TryGetValue("Headers", out string? msg_headers))
            {
                msg.Headers = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(msg_headers)!;
            }
            
            if (jsonDict.TryGetValue("Data", out string? msg_Data))
            {
                msg.Data = Convert.FromBase64String(msg_Data);
            }

            if (jsonDict.TryGetValue("QueryId", out string? msg_QueryId)) msg.QueryId = Guid.Parse(msg_QueryId!);
            return msg;
        }

        private byte[] SerializeBinaryBase()
        {
            MemoryStream memoryStream = new();
            BinaryWriter binaryWriter = new(memoryStream);

            binaryWriter.Write7BitEncodedInt(Headers.Count);
            foreach (var kv in Headers)
            {
                binaryWriter.Write(kv.Key);
                binaryWriter.Write(kv.Value);
            }

            binaryWriter.Write7BitEncodedInt(Data.Length); 
            if (Data.Length > 0) binaryWriter.Write(Data);
            binaryWriter.Write(QueryId.ToByteArray());
            binaryWriter.Write(IsQueryResponse);
            binaryWriter.Write(IsValid);

            return memoryStream.ToArray();
        }

        private static NetMessage DeSerializeBinaryBase(ArraySegment<byte> data, INetLink link)
        {
            NetMessage netMessage = new NetMessage(link);

            MemoryStream memorystream = new MemoryStream(data.Array!, data.Offset, data.Count);
            BinaryReader binaryReader = new(memorystream);

            int headersCount = binaryReader.Read7BitEncodedInt();
            while (headersCount-->0)
            {
                try
                {
                    string key = binaryReader.ReadString();
                    string val = binaryReader.ReadString();
                    netMessage.Headers.Add(key, val);
                }
                catch
                {

                }
            }
            int dataLen = binaryReader.Read7BitEncodedInt(); 
            if (dataLen > 0) netMessage.Data = binaryReader.ReadBytes(dataLen);
            netMessage.QueryId = new Guid(binaryReader.ReadBytes(16));
            netMessage.IsQueryResponse = binaryReader.ReadBoolean();
            netMessage.IsValid = binaryReader.ReadBoolean();

            return netMessage;
        }

        internal byte[] SerializeBinary(INetLink link)
        {
            NetLinkSharedBase linkb = (link as NetLinkSharedBase)!;
            RSA ? signingKey = null;
            RSA? encryptionKey = linkb.PublicKeyRsa;
            ICryptoTransform? encryptorAes = linkb.AesEncoder;

            byte[] baseMessageData = SerializeBinaryBase();

            MessageFlags flags = MessageFlags.None;
            if (linkb.AllowCompression) flags |= MessageFlags.Compressed; // TODO: Maybe skip compression below a certain size of message?
            if (signingKey != null) flags |= MessageFlags.Signed;
            
            if (encryptorAes != null) flags |= MessageFlags.EncryptedAes;
            else if (encryptionKey != null) flags |= MessageFlags.EncryptedRsa;

            // Compression
            byte[] preCompressedData = baseMessageData;
            byte[] postCompressedData = preCompressedData;
            if (flags.HasFlag(MessageFlags.Compressed))
            {
                MemoryStream compressionStream = new MemoryStream();
                using (DeflateStream dstream = new DeflateStream(compressionStream, CompressionLevel.Fastest))
                {
                    dstream.Write(preCompressedData, 0, preCompressedData.Length);
                }
                postCompressedData = compressionStream.ToArray();
            }

            // Sign
            byte[] preSignedData = postCompressedData;
            byte[] postSignedData = preSignedData;
            if (flags.HasFlag(MessageFlags.Signed))
            {
                byte[] signature = signingKey!.SignData(preSignedData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                postSignedData = Combine(signature, preSignedData);
            }

            // Encrypt
            byte[] preEncryptedData = postSignedData;
            byte[] postEncryptedData = preEncryptedData;
            if (flags.HasFlag(MessageFlags.EncryptedAes) && encryptorAes!=null)
            {
                postEncryptedData = Utilities.EncryptData(preEncryptedData, encryptorAes);
            }
            else if (flags.HasFlag(MessageFlags.EncryptedRsa) && encryptionKey!=null)
            {
                postEncryptedData = Utilities.EncryptData(preEncryptedData, encryptionKey);
            }

            byte[] finalData = postEncryptedData;

            // Prepend with flags byte
            byte[] finalBuffer = new byte[finalData.Length+1];
            finalBuffer[0] = (byte)flags;
            finalData.CopyTo(finalBuffer, 1);
            return finalBuffer;
        }

        internal static NetMessage DeSerializeBinary(ArraySegment<byte> data, INetLink link)
        {
            if (data.Count < 1) throw new ArgumentException("NetMessage data too short.");

            NetLinkSharedBase linkb = (link as NetLinkSharedBase)!;

            MessageFlags flags = (MessageFlags)data.ElementAt(0);

            ArraySegment<byte> rawData = new ArraySegment<byte>(data.Array!, 1, data.Count - 1);

            try
            {
                // Decryption
                ArraySegment<byte> encryptedData = rawData;
                ArraySegment<byte> decryptedData = encryptedData;
                if (flags.HasFlag(MessageFlags.EncryptedAes))
                {
                    ICryptoTransform? decryptorAes = linkb.AesDecoder;

                    // Give some time for AES key to arrive
                    int maxDelay = 1000; // Roughly 10 seconds
                    while (decryptorAes == null && maxDelay-- > 0)
                    {
                        Thread.Sleep(10);
                        decryptorAes = linkb.AesDecoder;
                    }

                    if (decryptorAes == null) 
                    { 
                        throw new ArgumentException("Message encrypted but no AES key provided."); 
                    }
                    decryptedData = Utilities.DecryptData(encryptedData, decryptorAes);
                }    
                else if (flags.HasFlag(MessageFlags.EncryptedRsa))
                {
                    RSA? decryptionKey = linkb.PrivateKeyRsa;
                    if (decryptionKey == null) 
                    { 
                        throw new ArgumentException("Message encrypted but no RSA key provided."); 
                    }
                    decryptedData = Utilities.DecryptData(encryptedData, decryptionKey);
                }

                // Signing validation
                ArraySegment<byte> signedData = decryptedData;
                ArraySegment<byte> unsignedData = signedData;
                bool verified = false;
                if (flags.HasFlag(MessageFlags.Signed))
                {
                    RSA? verificationKey = null;
                    if (verificationKey == null) { throw new ArgumentException("Message signed but no key provided."); }

                    int signatureLength = verificationKey.KeySize >> 3;
                    if ((signatureLength << 3) != verificationKey.KeySize) { throw new ArgumentException("Signing key length must be a power of two."); }
                    if (signedData.Count <= signatureLength) throw new InvalidDataException("Signed data malformed");
                    var signature = new ArraySegment<byte>(signedData.Array!, 0, signatureLength);
                    unsignedData = new ArraySegment<byte>(signedData.Array!, signatureLength, signedData.Count - signatureLength);
                
                    verified = verificationKey!.VerifyData(unsignedData, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                    if (!verified)
                    {
                        throw new ArgumentException("Data signature does not match the provided signature.");
                    }
                }

                // Decompression
                ArraySegment<byte> compressedData = unsignedData;
                ArraySegment<byte> decompressedData = compressedData;
                if (flags.HasFlag(MessageFlags.Compressed))
                {
                    MemoryStream input = new MemoryStream(compressedData.Array!, compressedData.Offset, compressedData.Count);
                    MemoryStream decompressionStream = new MemoryStream();
                    using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
                    {
                        dstream.CopyTo(decompressionStream);
                    }
                    decompressedData = decompressionStream.ToArray();
                }

                ArraySegment<byte> baseMessageData = decompressedData;

                try
                {
                    var msg = DeSerializeBinaryBase(baseMessageData, link);

                    msg.IsEncrypted = flags.HasFlag(MessageFlags.EncryptedRsa) || flags.HasFlag(MessageFlags.EncryptedAes);
                    msg.IsVerified = verified;
                    return msg;
                }
                catch (Exception e)
                {
                     throw new InvalidDataException($"Error deserializing net message(1): {e.Message}");
                }
            }
            catch (Exception e)
            {
                throw new InvalidDataException($"Error deserializing net message(2): {e.Message}");
            }
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] bytes = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
            Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
            return bytes;
        }
    }

    public abstract class NetLinkSharedBase
    {
        public Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler { private get; set; }
        public Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler { private get; set; }

        protected Dictionary<Guid, SemaphoreSlim> PendingRequests = new();
        protected Dictionary<Guid, NetMessage> PendingResponses = new();

        internal bool AllowEncryption { get; init; } = true;
        internal bool AllowCompression { get; init; } = true;

        internal bool IsInitiator { get; set; }
        internal bool IsClient { get; set; } = true;
        internal string Role => IsClient ? "Client" : "Server";

        private Guid? EncryptionRequestGuid;

        internal RSA? PrivateKeyRsa;
        internal RSA? PublicKeyRsa;

        internal ICryptoTransform? AesEncoder => (AesKey != null) ? Utilities.GetAesEncryptor(INetLink, AesKey) : null;
        internal ICryptoTransform? AesDecoder => (AesKey != null) ? Utilities.GetAesDecryptor(INetLink, AesKey) : null;
        internal byte[]? AesKey;

        //private RSA? ValidationKey { get; set; }

        protected INetLink INetLink => (this as INetLink)!;

        [System.Diagnostics.Conditional("DEBUG")]
        internal void Trace(string msg) => Utilities.Trace(msg);

        internal void ResetAtConnection()
        {
            PendingResponses?.Clear();
            if (PendingRequests != null)
            {
                foreach (var r in PendingRequests.Values) { r.Release(); }
                PendingRequests?.Clear();
            }

            PrivateKeyRsa = null;
            PublicKeyRsa = null;
            //ValidationKey = null;
            AesKey = null;
            EncryptionRequestGuid = null;
        }

        internal async Task InternalOnLinkEstablished(CancellationToken ct)
        {
            IsClient = false;

            if (AllowEncryption && !IsClient)
            {
                // Note: We are assuming that only the server initiates Encryption requests
                var serverCertificate = Utilities.GetCertificate(INetLinkServer.ServerCertificateName);
                if (Utilities.Verbose)
                {
                    if (serverCertificate != null) { Trace($"Server sending certificate: {serverCertificate.Issuer}"); }
                    else { Trace("Server does not have a certificate."); }
                }
                if (serverCertificate != null)
                {
                    await SendStartEncryption(serverCertificate, null, null, ct);
                }
            }
        }

        protected async Task<bool> SendMessage(NetMessage command, CancellationToken ct)
        {
            try
            {
                return await SendMessageImpl(command, ct);
            }
            catch (TaskCanceledException)
            {
                return false;
            }
        }

        protected abstract Task<bool> SendMessageImpl(NetMessage command, CancellationToken ct);

        protected async Task SendStartEncryption(X509Certificate2? cert, byte[]? aesKey, NetMessage? query, CancellationToken ct)
        {
            RSA pubKey = cert?.GetRSAPublicKey()!;

            NetMessage message = INetLink.CreateQuery("StartEncrypt");
            if (query != null)
            {
                //message.Headers.Add("command","AcceptEncrypt");
                message.QueryId = query.QueryId;
                message.IsQueryResponse = true;
            }

            if (aesKey != null)
            {
                message.Headers.Add("aesKey", Convert.ToBase64String(aesKey));
            }

            if (pubKey != null)
            {
                string pubKeyXml = pubKey.ToXmlString(includePrivateParameters: false);
                message.Data = System.Text.Encoding.UTF8.GetBytes(pubKeyXml);
            }
            else
            {
                Trace($"{Role} No RSA key provided.");
            }

            EncryptionRequestGuid = message.QueryId;
            await SendMessage(message, ct);
            if (ct.IsCancellationRequested) return;
            PrivateKeyRsa = cert?.GetRSAPrivateKey();
        }

        private void GetPublicKeyFromMessage(NetMessage msg)
        {
            if (msg.Data.Length > 0)
            {
                string pubKeyXml = System.Text.Encoding.UTF8.GetString(msg.Data);
                var pubRSA = RSA.Create();
                Trace($"{Role} {INetLink.Id} Received public Key{pubKeyXml}");
                pubRSA.FromXmlString(pubKeyXml);
                PublicKeyRsa = pubRSA;
            }
        }

        protected async Task HandleMessageReception(NetMessage msg, CancellationToken ct)
        {
            // Handle queries
            if (msg.QueryId != Guid.Empty)
            {
                if (msg.GetQuery() == "StartEncrypt" && !msg.IsQueryResponse)
                {
                    GetPublicKeyFromMessage(msg);

                    // Client choses an AES encrytion key
                    byte[] aesKey = Utilities.GenerateAesKey();

                    // Note: We are assuming that only the client responds Encryption requests
                    var clientCertificate = Utilities.GetCertificate(INetLinkServer.ClientCertificateName);
                    if (Utilities.Verbose)
                    {
                        if (clientCertificate != null) { Trace($"Client sending certificate: {clientCertificate.Issuer}"); }
                        else { Trace("Client does not have a certificate."); }
                    }

                    await SendStartEncryption(clientCertificate, aesKey, msg, ct);
                    Trace($"{Role} AES key set: {Convert.ToBase64String(aesKey)}");
                    AesKey = aesKey;
                }
                else if (msg.QueryId == EncryptionRequestGuid)
                {
                    // Server receive ecryption query response
                    GetPublicKeyFromMessage(msg);

                    if (msg.Headers.TryGetValue("aesKey", out string? aesKeyStr))
                    {
                        byte[] aesKey = Convert.FromBase64String(aesKeyStr);
                        Trace($"{Role} AES key set: {Convert.ToBase64String(aesKey)}");
                        AesKey = aesKey;
                    }
                    EncryptionRequestGuid = null;
                }
                else if (msg.IsQueryResponse)
                {
                    Trace($"{Role} Query response received: {msg}");

                    SemaphoreSlim? semaphore;
                    int maxTries = 100;
                    while (!PendingRequests.TryGetValue(msg.QueryId, out semaphore))
                    {
                        if (maxTries-- <= 0) throw new InvalidOperationException($"{Role} Pending request not found.");
                        await Task.Delay(1);
                    }

                    PendingResponses.Add(msg.QueryId, msg);
                    semaphore.Release();
                    PendingRequests.Remove(msg.QueryId);
                }
                else
                {
                    Trace($"{Role} Query received: {msg}");

                    if (QueryHandler != null)
                    {
                        try
                        {
                            var response = await QueryHandler.Invoke(INetLink, msg, ct);
                            await SendMessage(response, ct);
                        }
                        catch (TaskCanceledException)
                        {
                            Trace($"{Role} Response processing cancelled.");
                        }
                    }
                    else
                    {
                        // Default response
                        var response = INetLink.CreateResponse(msg, true, string.Empty);
                        await SendMessage(response, ct);
                    }
                }
            }
            else
            {
                Trace($"{Role} Command received: {msg}");

                if (msg.GetCommand() == "StartEncrypt")
                {

                }
                else if (CommandHandler != null)
                {
                    await CommandHandler.Invoke(INetLink, msg, ct);
                }
            }

        }

        protected async Task<NetMessage> WaitResponse(NetMessage query, CancellationToken ct)
        {
            Trace($"{Role} Query sent, waiting for response: {query}");

            SemaphoreSlim requestSemaphore = new(0);
            PendingRequests.Add(query.QueryId, requestSemaphore);
            await requestSemaphore.WaitAsync(ct);
            if (PendingResponses.TryGetValue(query.QueryId, out var resp))
            {
                PendingResponses.Remove(query.QueryId);
                return resp;
            }
            else
            {
                return INetLink.CreateResponse(query, false, $"{Role} No response found");
            }
        }
    }
}
