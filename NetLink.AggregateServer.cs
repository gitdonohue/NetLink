// SPDX-License-Identifier: MIT

namespace NetLink;

public sealed class NetLinkAggregateServer : INetLinkServer
{
    public bool AllowEncryption { get; init; } = true;
    public bool AllowOutgoingCompression { get; init; } = true;

    public event Action<INetLink>? LinkEstablished;
    public event Action<INetLink>? LinkTerminated;


    public Func<INetLink, NetMessage, CancellationToken, Task>? CommandHandler 
    { 
        set
        {
            foreach (var server in Servers) { server.CommandHandler = value; }
        }
    }

    public Func<INetLink, NetMessage, CancellationToken, Task<NetMessage>>? QueryHandler 
    {
        set
        {
            foreach (var server in Servers) { server.QueryHandler = value; }
        }
    }

    private HashSet<INetLinkServer> Servers = new();
    public NetLinkAggregateServer(IEnumerable<INetLinkServer> linkServers)
    {
        foreach(var server in linkServers)
        {
            Servers.Add(server);
            server.LinkEstablished += (link) => LinkEstablished?.Invoke(link);
            server.LinkTerminated += (link) => LinkTerminated?.Invoke(link);
        }
    }

    public void Dispose()
    {
        foreach (var server in Servers) 
        {
            server.Dispose();
        }
        Servers.Clear();
    }

    public IEnumerable<INetLink> GetLinks()
    {
        foreach (var server in Servers)
        {
            foreach(var link in server.GetLinks())
            {
                yield return link;
            }
        }
    }

    public async Task Run(CancellationToken ct)
    {
        await Task.WhenAll( Servers.Select(async x => await x.Run(ct) ) );
    }
}
