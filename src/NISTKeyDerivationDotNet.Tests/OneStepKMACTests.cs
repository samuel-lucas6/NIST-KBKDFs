namespace NISTKeyDerivationDotNet.Tests;

[TestClass]
public class OneStepKMACTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "4baea80d0ec72fbbf0cb27d13fb58551",
            "6ee6c00d70a6cd14bd5a4e8fcfec8386",
            "532f5131e0a2fecc722f87e5aa2062cb",
            "861aa2886798231259bd0314",
            KmacVariant.KMAC128
        };
        yield return new object[]
        {
            "9020aec6514ab09044c1639c7f5ce93b",
            "0031558fddb96e3db2e0496026302055",
            "1ae1",
            "97ed3540c7466ab27395fe79",
            KmacVariant.KMAC128
        };
        yield return new object[]
        {
            "452c4436bc6f578f9ae9fb086f1ffc6bc28e1f7abdabcb671c7728f27ea2057ca72e965f03ac3165",
            "3bd9a074a219d62273c3f639659a3ecd",
            "6199187690823def2037e0632577c6b1",
            "",
            KmacVariant.KMAC128
        };
        yield return new object[]
        {
            "d62a16e28017cec2",
            "a801d997ed539ae9aa05d17871eb7fab",
            "",
            "03697296e42a6fdbdb24b3ec",
            KmacVariant.KMAC128
        };
        yield return new object[]
        {
            "d1652412b7e2756cfb1ab7fc9d9c5af0",
            "6ee6c00d70a6cd14bd5a4e8fcfec8386",
            "532f5131e0a2fecc722f87e5aa2062cb",
            "861aa2886798231259bd0314",
            KmacVariant.KMAC256
        };
        yield return new object[]
        {
            "b9320fa010a42819ef12dcfb2b2175ff",
            "0031558fddb96e3db2e0496026302055",
            "1ae1",
            "97ed3540c7466ab27395fe79",
            KmacVariant.KMAC256
        };
        yield return new object[]
        {
            "8e9f7d6cf5fa8d9e0be22eb35d6bf11ef62fd500ae4eeda0adf4678ad264fbe073fbbc04e5f27c84",
            "3bd9a074a219d62273c3f639659a3ecd",
            "6199187690823def2037e0632577c6b1",
            "",
            KmacVariant.KMAC256
        };
        yield return new object[]
        {
            "6e7221b7d8fe6b8a",
            "a801d997ed539ae9aa05d17871eb7fab",
            "",
            "03697296e42a6fdbdb24b3ec",
            KmacVariant.KMAC256
        };
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string derivedKeyingMaterial, string sharedSecret, string salt, string fixedInfo, KmacVariant kmacVariant)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> ss = Convert.FromHexString(sharedSecret);
        Span<byte> s = Convert.FromHexString(salt);
        Span<byte> fi = Convert.FromHexString(fixedInfo);

        OneStepKMAC.DeriveKey(dkm, ss, s, fi, kmacVariant);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, 32, 16, 12, KmacVariant.KMAC128)]
    [DataRow(32, 0, 16, 12, KmacVariant.KMAC128)]
    public void DeriveKey_Invalid(int derivedKeyingMaterialSize, int sharedSecretSize, int saltSize, int fixedInfoSize, KmacVariant kmacVariant)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var ss = new byte[sharedSecretSize];
        var s = new byte[saltSize];
        var fi = new byte[fixedInfoSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => OneStepKMAC.DeriveKey(dkm, ss, s, fi, kmacVariant));
    }
}
