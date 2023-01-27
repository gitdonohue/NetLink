// To create a certificate which includes a private key:
// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 900 -nodes
// openssl pkcs12 -inkey key.pem -in cert.pem -export -out NetLinkServer.pfx
// Note: If you have Git installed, you can typically find openssl.exe here:
//       "c:\Program Files\Git\usr\bin\openssl.exe"
// Or
// https://certificatetools.com/

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetLink
{
    internal static partial class Utilities
    {
        internal static byte[] EncryptData(ArraySegment<byte> data, RSA encryptionKey)
        {
            MemoryStream memoryStream = new();
            BinaryWriter binaryWriter = new(memoryStream);
            int blockSize = encryptionKey.KeySize / 8 - 2 * 256 / 8 - 2;
            foreach (var chunk in EnumerateChunks(data, blockSize))
            {
                var chunkBuffer = ToArray(chunk);
                var outbuff = encryptionKey.Encrypt(chunkBuffer, RSAEncryptionPadding.OaepSHA256);
                binaryWriter.Write7BitEncodedInt(outbuff.Length);
                binaryWriter.Write(outbuff);
            }
            return memoryStream.ToArray();
        }

        internal static byte[] DecryptData(ArraySegment<byte> data, RSA decryptionKey)
        {
            MemoryStream memoryStream = new();
            BinaryWriter binaryWriter = new(memoryStream);
            BinaryReader binaryReader = new(new MemoryStream(data.Array!, data.Offset, data.Count));

            while (binaryReader.BaseStream.Position < binaryReader.BaseStream.Length)
            {
                int blockLength = binaryReader.Read7BitEncodedInt();
                var e = binaryReader.ReadBytes(blockLength);
                var d = decryptionKey.Decrypt(e, RSAEncryptionPadding.OaepSHA256);
                binaryWriter.Write(d);
            }

            return memoryStream.ToArray();
        }

        internal static byte[] EncryptData(ArraySegment<byte> data, ICryptoTransform encryptor)
        {
            MemoryStream memoryStream = new();
            BinaryWriter binaryWriter = new(memoryStream);
            binaryWriter.Write(data.Count); // write unencrypted length
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter bw = new BinaryWriter(csEncrypt))
                    {
                        bw.Write(data);
                    }

                    var encryptedBuffer = msEncrypt.ToArray();
                    binaryWriter.Write(encryptedBuffer);
                }
            }
            binaryWriter.Flush();
            return memoryStream.ToArray();
        }

        internal static byte[] DecryptData(ArraySegment<byte> data, ICryptoTransform decryptor)
        {
            ArraySegment<byte> encryptedData = new(data.Array!, data.Offset + 4, data.Count - 4);
            BinaryReader binaryReader = new(new MemoryStream(data.Array!, data.Offset, 4));
            int decryptedLength = binaryReader.ReadInt32();
            using (MemoryStream msDecrypt = new MemoryStream(data.Array!, data.Offset +4, data.Count - 4))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))
                    {
                        var buffer = new byte[decryptedLength];
                        int offset = 0;
                        int total = decryptedLength;
                        while (total > 0)
                        {
                            int n = srDecrypt.Read(buffer, offset, total);
                            if (n <= 0) break;
                            total -= n;
                            offset += n;
                        }
                        return buffer;
                    }
                }
            }
            throw new InvalidDataException("Could not decrypt data.");
        }

        private static Dictionary<string, X509Certificate2?> CertificateCache = new();
        internal static X509Certificate2? GetCertificate(string certificateName)
        {
            // Retreive from cache
            if (CertificateCache.TryGetValue(certificateName, out X509Certificate2? cert)) { return cert; }

            var localStores = new List<StoreLocation>() { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
            foreach (var storeLocation in localStores)
            {
                var certificateStore = new X509Store(storeLocation);
                certificateStore.Open(OpenFlags.ReadOnly);
                cert = certificateStore.Certificates.LastOrDefault(x => x.Issuer == certificateName
                    || x.Issuer.Split(',').Any(x => x.Trim() == $"CN={certificateName}"));
                if (cert != null) break;
            }

            // Validate private key
            if (cert != null)
            {
                try
                {
                    cert.GetRSAPrivateKey();
                }
                catch (Exception)
                {
                    throw new ArgumentException($"The certificate does not contain a valid private key.");
                }
            }

            CertificateCache.Add(certificateName, cert);
            return cert;
        }

        internal static byte[] GenerateAesKey() => Guid.NewGuid().ToByteArray();

        internal static ICryptoTransform GetAesEncryptor(INetLink link, byte[] key)
        {
            try
            {
                Aes aesAlg = Aes.Create();
                aesAlg.Key = key;
                aesAlg.IV = link.Id.ToByteArray();
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                return encryptor;
            }
            catch (Exception e)
            {
                Trace($"Error initializing AES: {e.Message}");
                throw;
            }
        }

        internal static ICryptoTransform GetAesDecryptor(INetLink link, byte[] key)
        {
            try
            {
                Aes aesAlg = Aes.Create();
                aesAlg.Key = key;
                aesAlg.IV = link.Id.ToByteArray();
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                return decryptor;
            }
            catch (Exception e)
            {
                Trace($"Error initializing AES: {e.Message}");
                throw;
            }
        }
    }
}
