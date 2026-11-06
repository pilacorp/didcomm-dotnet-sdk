using System.Net;
using System.Net.Sockets;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

/// <summary>
/// SSRF guard for HTTP DID resolution: only http/https are allowed, and (unless
/// explicitly permitted) the target host must not resolve to a loopback,
/// link-local, private or otherwise non-public address. Pair with disabled
/// auto-redirects and a response-size cap on the HTTP client.
/// </summary>
public static class ResolverGuard
{
    /// <summary>
    /// Throws when <paramref name="url"/> is not a safe resolution target.
    /// When <paramref name="allowPrivateHosts"/> is false, loopback / link-local
    /// / private / unspecified addresses are rejected.
    /// </summary>
    public static void ValidateUrl(string url, bool allowPrivateHosts)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"DID resolver URL is not absolute: {url}");
        }
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException(
                $"DID resolver URL scheme '{uri.Scheme}' is not allowed (only http/https)");
        }
        if (allowPrivateHosts)
        {
            return;
        }

        foreach (var addr in HostAddresses(uri))
        {
            if (IsBlocked(addr))
            {
                throw new InvalidOperationException(
                    $"DID resolver host '{uri.Host}' resolves to blocked address {addr} (private/loopback/link-local)");
            }
        }
    }

    private static IEnumerable<IPAddress> HostAddresses(Uri uri)
    {
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            return new[] { literal };
        }
        if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new[] { IPAddress.Loopback };
        }
        try
        {
            return Dns.GetHostAddresses(uri.Host);
        }
        catch (SocketException)
        {
            // Unresolvable host: treat as blocked by returning an unspecified addr.
            return new[] { IPAddress.Any };
        }
    }

    private static bool IsBlocked(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr) || addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any))
        {
            return true;
        }
        if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6UniqueLocal)
        {
            return true;
        }
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 (CGNAT)
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
        }
        return false;
    }

    private static readonly IPNetwork[] NonPublic = new[]
    {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24", "192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32", "3fff::/20", "5f00::/16",
        "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    }.Select(IPNetwork.Parse).ToArray();

    /// <summary>
    /// Strict check used for @context fetches (table of go processor.isPublicAddr: the IANA special-purpose
    /// registries' non-global entries plus multicast and site-local). An IPv6 address carrying an IPv4 address
    /// (mapped, ::/96, NAT64, 6to4) is judged by that IPv4 address.
    /// </summary>
    public static bool IsPublicAddress(IPAddress ip)
    {
        var b = ip.GetAddressBytes(); // the scope id is dropped
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            ip = new IPAddress(b);
            if (ip.IsIPv4MappedToIPv6 || IPNetwork.Parse("::/96").Contains(ip) || IPNetwork.Parse("64:ff9b::/96").Contains(ip))
                ip = new IPAddress(b[12..16]);
            else if (b[0] == 0x20 && b[1] == 0x02)
                ip = new IPAddress(b[2..6]);
        }
        return !NonPublic.Any(n => n.Contains(ip));
    }
}
