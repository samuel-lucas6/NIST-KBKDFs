namespace NISTKeyDerivationDotNet.Tests;

[TestClass]
public class OneStepHMACTests
{
    // https://crypto.stackexchange.com/questions/64140/where-can-i-find-official-test-vectors-for-nist-sp-800-56c-r1-single-step-kdf
    // https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "13479e9a91dd20fdd757d68ffe8869fb",
            "6ee6c00d70a6cd14bd5a4e8fcfec8386",
            "532f5131e0a2fecc722f87e5aa2062cb",
            "861aa2886798231259bd0314",
            "SHA256"
        };
        yield return new object[]
        {
            "ddf7eedcd997eca3943d4519aaf414f4",
            "0031558fddb96e3db2e0496026302055",
            "1ae1",
            "97ed3540c7466ab27395fe79",
            "SHA256"
        };
        yield return new object[]
        {
            "cc45eb2ab80272c1e082b4f167ee4e086f12af3fbd0c812dda5568fea702928999cde3899cffc8a8",
            "3bd9a074a219d62273c3f639659a3ecd",
            "6199187690823def2037e0632577c6b1",
            "",
            "SHA256"
        };
        yield return new object[]
        {
            "1a5efa3aca87c1f4",
            "a801d997ed539ae9aa05d17871eb7fab",
            "",
            "03697296e42a6fdbdb24b3ec",
            "SHA256"
        };
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string derivedKeyingMaterial, string sharedSecret, string salt, string fixedInfo, string hashAlgorithmName)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> ss = Convert.FromHexString(sharedSecret);
        Span<byte> s = Convert.FromHexString(salt);
        Span<byte> fi = Convert.FromHexString(fixedInfo);

        OneStepHMAC.DeriveKey(dkm, ss, s, fi, new HashAlgorithmName(hashAlgorithmName));

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, 32, 16, 12, "SHA256")]
    [DataRow(32, 0, 16, 12, "SHA256")]
    [DataRow(32, 32, 16, 12, "MD5")]
    [DataRow(32, 32, 16, 12, "SHA1")]
    public void DeriveKey_Invalid(int derivedKeyingMaterialSize, int sharedSecretSize, int saltSize, int fixedInfoSize, string hashAlgorithmName)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var ss = new byte[sharedSecretSize];
        var s = new byte[saltSize];
        var fi = new byte[fixedInfoSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => OneStepHMAC.DeriveKey(dkm, ss, s, fi, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => OneStepHMAC.DeriveKey(dkm, ss, s, fi, new HashAlgorithmName(hashAlgorithmName)));
        }
    }
}
