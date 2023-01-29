using System.Net;

namespace NetLink
{
    internal static partial class Utilities
    {
        internal static bool Verbose => INetLink.Verbose;
        [System.Diagnostics.Conditional("DEBUG")] internal static void Trace(string msg) { if (Verbose) Console.WriteLine(msg); System.Diagnostics.Debug.WriteLine(msg); }

        public static async Task<T?> WithCancellationToken<T>(this Task<T> source, CancellationToken cancellationToken)
        {
            var cancellationTask = new TaskCompletionSource<bool>();
            cancellationToken.Register(() => cancellationTask.SetCanceled());

            _ = await Task.WhenAny(source, cancellationTask.Task);

            if (cancellationToken.IsCancellationRequested)
                return default;
            return source.Result;
        }

        internal static byte[] ToArray(ArraySegment<byte> s) => new ReadOnlySpan<byte>(s.Array, s.Offset, s.Count).ToArray();

        internal static IEnumerable<ArraySegment<byte>> EnumerateChunks(ArraySegment<byte> data, int chunkSize)
        {
            if (data.Count <= chunkSize) yield return data;
            else
            {
                byte[] dataBuffer = data.Array!;
                int totalLength = dataBuffer.Length;
                int offset = data.Offset;
                while (true)
                {
                    if ((offset + chunkSize) >= totalLength)
                    {
                        yield return new ArraySegment<byte>(dataBuffer, offset, totalLength - offset);
                        break;
                    }
                    else
                    {
                        yield return new ArraySegment<byte>(dataBuffer, offset, chunkSize);
                    }
                    offset += chunkSize;
                }
            }
        }

        internal static IPAddress GetServerAddress(string serverName)
        {
            if (!IPAddress.TryParse(serverName, out var serverAddr)) // 1st try for server explicitly set as www.xxx.yyy.zzz
            {
                if (serverName == "auto")
                {
                    string hostName = Dns.GetHostName();
                    var machineIPs = Dns.GetHostEntry(hostName, System.Net.Sockets.AddressFamily.InterNetwork).AddressList;
                    if (machineIPs == null) throw new InvalidOperationException($"Hostname {serverName} not valid.");
                    serverAddr = machineIPs.First();
                }
                else
                {
                    var localAddresses = Dns.GetHostEntry(serverName);
                    if (localAddresses == null) throw new InvalidOperationException($"Hostname {serverName} not valid.");
                    serverAddr = localAddresses.AddressList.First();
                }
            }
            return serverAddr;
        }

        internal static string ReadUtf8String(this BinaryReader reader)
        {
            int len = reader.Read7BitEncodedInt();
            byte[] buffer = new byte[len];
            reader.Read(buffer, 0, len);
            return System.Text.Encoding.UTF8.GetString(buffer);
        }

        internal static void WriteUtf8String(this BinaryWriter writer, string s)
        {
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(s);
            writer.Write7BitEncodedInt(buffer.Length);
            writer.Write(buffer);
        }

        // Helper method to avoid having to use try finally blocks to lock the semaphore
        public sealed class SemaphoreLock : IDisposable
        {
            public bool Verbose { get; set; } = false;
            [System.Diagnostics.Conditional("DEBUG")] private void Trace(string msg) { if (Verbose) Utilities.Trace(msg); }

            public static IDisposable AcquireLock(SemaphoreSlim semaphore, CancellationToken ct = default)
            {
                var semaphoreAutoReleaseLock = new SemaphoreLock(semaphore);
                semaphoreAutoReleaseLock.Wait(ct);
                return semaphoreAutoReleaseLock;
            }

            public static async Task<IDisposable> AcquireLockAsync(SemaphoreSlim semaphore, CancellationToken ct, string debugName = "")
            {
                var semaphoreAutoReleaseLock = new SemaphoreLock(semaphore, debugName);
                await semaphoreAutoReleaseLock.WaitAsync(ct);
                if (ct.IsCancellationRequested) throw new OperationCanceledException();
                return semaphoreAutoReleaseLock;
            }

            SemaphoreSlim Semaphore;
            bool WasBusy;
            string Name = "";

            private SemaphoreLock(SemaphoreSlim semaphore, string? debugName = null)
            {
                Semaphore = semaphore;
                Name = debugName ?? string.Empty;
                WasBusy = semaphore.CurrentCount == 0;
                if (Verbose)
                {
                    if (WasBusy) { Trace($"{Name} Semaphore busy..."); }
                }
            }

            private void Wait(CancellationToken ct)
            {
                Semaphore.Wait(ct);
                if (WasBusy) { Trace($"{Name} Semaphore wait complete."); }
            }

            private async Task WaitAsync(CancellationToken ct)
            {
                await Semaphore.WaitAsync(ct);
                if (WasBusy) { Trace($"{Name} Semaphore wait complete."); }
            }

            public void Dispose()
            {
                if (Verbose && WasBusy) Trace($"{Name} Semaphore Released.");
                Semaphore.Release();
            }
        }
    }
}
