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
}
