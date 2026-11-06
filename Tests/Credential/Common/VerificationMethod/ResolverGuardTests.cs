using System;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.VerificationMethod;

public class ResolverGuardTests
{
    [Theory]
    [InlineData("http://127.0.0.1/did")]
    [InlineData("http://localhost:8080/did")]
    [InlineData("http://169.254.169.254/latest/meta-data")] // link-local / cloud metadata
    [InlineData("http://10.0.0.5/did")]
    [InlineData("http://192.168.1.1/did")]
    [InlineData("http://172.16.0.1/did")]
    [InlineData("http://[::1]/did")]
    public void BlocksPrivateHosts_WhenNotAllowed(string url)
    {
        Assert.Throws<InvalidOperationException>(() => ResolverGuard.ValidateUrl(url, allowPrivateHosts: false));
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com/x")]
    [InlineData("gopher://example.com/x")]
    public void BlocksNonHttpSchemes(string url)
    {
        Assert.Throws<InvalidOperationException>(() => ResolverGuard.ValidateUrl(url, allowPrivateHosts: true));
    }

    [Fact]
    public void AllowsPublicHttps()
    {
        // Public IP literal so the check does not depend on live DNS.
        ResolverGuard.ValidateUrl("https://8.8.8.8/api/v1/did/did%3Aexample%3Ax", allowPrivateHosts: false);
    }

    [Fact]
    public void AllowsLoopback_WhenExplicitlyAllowed()
    {
        // Operator-configured loopback base URL (used by interop tests) stays allowed.
        ResolverGuard.ValidateUrl("http://127.0.0.1:5000/did", allowPrivateHosts: true);
    }

    [Fact]
    public void RejectsRelativeUrl()
    {
        Assert.Throws<InvalidOperationException>(() => ResolverGuard.ValidateUrl("/did/x", allowPrivateHosts: true));
    }
}
