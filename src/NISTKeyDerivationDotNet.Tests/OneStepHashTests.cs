namespace NISTKeyDerivationDotNet.Tests;

[TestClass]
public class OneStepHashTests
{
    // https://crypto.stackexchange.com/questions/64140/where-can-i-find-official-test-vectors-for-nist-sp-800-56c-r1-single-step-kdf
    // https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "f0b80d6ae4c1e19e2105a37024e35dc6",
            "afc4e154498d4770aa8365f6903dc83b",
            "662af20379b29d5ef813e655",
            "SHA256"
        ];
        yield return
        [
            "a7c0",
            "3f892bd8b84dae64a782a35f6eaa8f00",
            "ec3f1cd873d28858a58cc39e",
            "SHA256"
        ];
        yield return
        [
            "67bc327d9aaf7be2d24b3d04ee200535",
            "3643",
            "ec7299bc411e17d6a69bd4e7",
            "SHA256"
        ];
        yield return
        [
            "25425fc7b4175fd4ee18668a3b133ff64e662256723cf1b9db24bf2902338fd7bfa957f5f8973e87d4aba29fc1feac5c09ecd9e99c79bbd1",
            "1dd60aecf2a1ae3957522acc4eba704c",
            "",
            "SHA256"
        ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string derivedKeyingMaterial, string sharedSecret, string fixedInfo, string hashAlgorithmName)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> ss = Convert.FromHexString(sharedSecret);
        Span<byte> fi = Convert.FromHexString(fixedInfo);

        OneStepHash.DeriveKey(dkm, ss, fi, new HashAlgorithmName(hashAlgorithmName));

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, 32, 12, "SHA256")]
    [DataRow(32, 0, 12, "SHA256")]
    [DataRow(32, 32, 12, "MD5")]
    [DataRow(32, 32, 12, "SHA1")]
    public void DeriveKey_Invalid(int derivedKeyingMaterialSize, int sharedSecretSize, int fixedInfoSize, string hashAlgorithmName)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var ss = new byte[sharedSecretSize];
        var fi = new byte[fixedInfoSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => OneStepHash.DeriveKey(dkm, ss, fi, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => OneStepHash.DeriveKey(dkm, ss, fi, new HashAlgorithmName(hashAlgorithmName)));
        }
    }
}
