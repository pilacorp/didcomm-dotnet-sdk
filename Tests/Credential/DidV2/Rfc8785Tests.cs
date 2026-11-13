using System.Text;
using Pila.CredentialSdk.DidComm.Credential.DidV2;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class Rfc8785Tests
{
    private static string C(string json) => Encoding.UTF8.GetString(Rfc8785.Transform(json));

    // Expected outputs were produced by Go's jsoncanonicalizer.Transform (same vectors as the TS SDK).
    [Theory]
    [InlineData("{\"z\":0,\"a\":[true,false,null,\"x\"]}", "{\"a\":[true,false,null,\"x\"],\"z\":0}")]
    [InlineData("{\"\\uE000\":1,\"\\uD83D\\uDE00\":2,\"b\":3}", "{\"b\":3,\"\U0001F600\":2,\"\uE000\":1}")]
    [InlineData("{\"b\":1,\"a\":2,\"10\":\"ten\",\"2\":\"two\"}", "{\"10\":\"ten\",\"2\":\"two\",\"a\":2,\"b\":1}")]
    [InlineData("{\"n\":[1.0,1e+21,1e+20,1e-6,1e-7,-0,0.0000012345,123456789012345.67]}",
        "{\"n\":[1,1e+21,100000000000000000000,0.000001,1e-7,0,0.0000012345,123456789012345.67]}")]
    [InlineData("{\"s\":\"\\u0000\\b\\t\\n\\f\\r\\\"\\\\\\/é😀\"}", "{\"s\":\"\\u0000\\b\\t\\n\\f\\r\\\"\\\\/é😀\"}")]
    [InlineData("{\"nested\":{\"z\":1,\"a\":{\"y\":2,\"x\":3}},\"array\":[{\"b\":2,\"a\":1},3]}",
        "{\"array\":[{\"a\":1,\"b\":2},3],\"nested\":{\"a\":{\"x\":3,\"y\":2},\"z\":1}}")]
    public void GoVectors(string input, string expected) => Assert.Equal(expected, C(input));

    [Fact]
    public void NumbersAreShortestEs6ThroughFloat64()
    {
        Assert.Equal("[0.1,1e+21,9007199254740992,-1.5,1e-7]", C("[0.1,1e21,9007199254740993,-1.5,1E-7]"));
    }

    [Fact]
    public void IsoDateStringStaysString() =>
        Assert.Equal("{\"d\":\"2020-01-01T00:00:00Z\"}", C("{\"d\":\"2020-01-01T00:00:00Z\"}"));

    [Fact]
    public void SurrogatePairKeyOrdersByUtf16Units()
    {
        // U+1F600 is D83D DE00 in UTF-16, so it sorts before U+E000.
        var s = C("{\"\\uE000\":1,\"\\uD83D\\uDE00\":2}");
        Assert.True(s.IndexOf("\U0001F600", StringComparison.Ordinal) < s.IndexOf("\uE000", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")]
    [InlineData("{\"a\":1,\"\\u0061\":2}")]
    [InlineData("1")]
    [InlineData("\"x\"")]
    [InlineData("null")]
    [InlineData("{\"a\":\"\\ud800\"}")]
    [InlineData("{\"\\udfff\":1}")]
    [InlineData("{\"a\":1e999}")]
    [InlineData("{\"a\":1} x")]
    [InlineData("{\"a\":1,}")]
    public void Rejects(string input) => Assert.Throws<InvalidOperationException>(() => Rfc8785.Transform(input));

    [Fact]
    public void DepthCap()
    {
        var ok = new string('[', 200) + new string(']', 200);
        Assert.Equal(ok, C(ok));
        var deep = new string('[', 201) + new string(']', 201);
        var ex = Assert.Throws<InvalidOperationException>(() => Rfc8785.Transform(deep));
        Assert.Contains("nesting exceeds maximum depth", ex.Message);
        var huge = new string('[', 1_000_000);
        Assert.Throws<InvalidOperationException>(() => Rfc8785.Transform(huge));
    }
}
