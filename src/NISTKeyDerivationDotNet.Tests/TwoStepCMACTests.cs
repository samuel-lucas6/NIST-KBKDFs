namespace NISTKeyDerivationDotNet.Tests;

[TestClass]
public class TwoStepCMACTests
{
    // https://github.com/google/wycheproof/blob/master/testvectors/aes_cmac_test.json
    public static IEnumerable<object[]> ExtractTestVectors()
    {
        yield return
        [
            "15f856bbed3b321952a584b3c4437a63",
            "3f",
            "e1e726677f4893890f8c027f9d8ef80d",
            CmacVariant.Aes128
        ];
        yield return
        [
            "ab20a6cf60873665b1d6999b05c7f9c6",
            "0e239f239705b282ce2200fe20de1165",
            "f4bfa5aa4f0f4d62cf736cd2969c43d580fdb92f2753bedb",
            CmacVariant.Aes192
        ];
        yield return
        [
            "925f177d85ea297ef14b203fe409f9ab",
            "91a17e4dfcc3166a1add26ff0e7c12056e8a654f28a6de24f4ba739ceb5b5b18",
            "96e1e4896fb2cd05f133a6a100bc5609a7ac3ca6d81721e922dadd69ad07a892",
            CmacVariant.Aes256
        ];
    }

    // The NIST test vectors predate the key control mitigation. Unable to find other test vectors
    public static IEnumerable<object[]> CounterModeTestVectors()
    {
        yield return
        [
            "73903b35f5b8c0e086780823b8a4ef19a82ecd271df907ab6c60e9203fc1d08b",
            "e1e726677f4893890f8c027f9d8ef80d",
            "4145414420656e6372797074696f6e",
            "416c69636520616e6420426f62",
            true,
            true
        ];
    }

    public static IEnumerable<object[]> FeedbackModeTestVectors()
    {
        yield return
        [
            "45577f94e9f7d297e184e0ab5292ca2ce3588819134ce1e4c0181a1f4b3235cf",
            "e1e726677f4893890f8c027f9d8ef80d",
            "4145414420656e6372797074696f6e",
            "416c69636520616e6420426f62",
            true,
            true
        ];
    }

    public static IEnumerable<object[]> DoublePipelineModeTestVectors()
    {
        yield return
        [
            "45577f94e9f7d297e184e0ab5292ca2c12289bba03d8e1feb59b0ad013952c79",
            "e1e726677f4893890f8c027f9d8ef80d",
            "4145414420656e6372797074696f6e",
            "416c69636520616e6420426f62",
            true,
            true
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ 0, TwoStepCMAC.KeyDerivationKeySize, 16, 32 ];
        yield return [ (int)(uint.MaxValue / 8 + 1), TwoStepCMAC.KeyDerivationKeySize, 16, 32 ];
        yield return [ 32, TwoStepCMAC.KeyDerivationKeySize + 1, 16, 32 ];
        yield return [ 32, TwoStepCMAC.KeyDerivationKeySize - 1, 16, 32 ];
    }

    [TestMethod]
    [DynamicData(nameof(ExtractTestVectors), DynamicDataSourceType.Method)]
    public void Extract_Valid(string keyDerivationKey, string sharedSecret, string salt, CmacVariant cmacVariant)
    {
        Span<byte> kdk = stackalloc byte[keyDerivationKey.Length / 2];
        Span<byte> ss = Convert.FromHexString(sharedSecret);
        Span<byte> s = Convert.FromHexString(salt);

        TwoStepCMAC.Extract(kdk, ss, s, cmacVariant);

        Assert.AreEqual(keyDerivationKey, Convert.ToHexString(kdk).ToLower());
    }

    [TestMethod]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize + 1, 32, (int)CmacVariant.Aes128, CmacVariant.Aes128)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize - 1, 32, (int)CmacVariant.Aes128, CmacVariant.Aes128)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 0, (int)CmacVariant.Aes128, CmacVariant.Aes128)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes128 + 1, CmacVariant.Aes128)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes128 - 1, CmacVariant.Aes128)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes192 + 1, CmacVariant.Aes192)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes192 - 1, CmacVariant.Aes192)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes256 + 1, CmacVariant.Aes256)]
    [DataRow(TwoStepCMAC.KeyDerivationKeySize, 32, (int)CmacVariant.Aes256 - 1, CmacVariant.Aes256)]
    public void Extract_Invalid(int keyDerivationKeySize, int sharedSecretSize, int saltSize, CmacVariant cmacVariant)
    {
        var kdk = new byte[keyDerivationKeySize];
        var ss = new byte[sharedSecretSize];
        var s = new byte[saltSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepCMAC.Extract(kdk, ss, s, cmacVariant));
    }

    [TestMethod]
    [DynamicData(nameof(CounterModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandCounterMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string label, string context, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepCMAC.ExpandCounterMode(dkm, kdk, l, c, useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ExpandCounterMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int labelSize, int contextSize)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepCMAC.ExpandCounterMode(dkm, kdk, l, c));
    }

    [TestMethod]
    [DynamicData(nameof(FeedbackModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandFeedbackMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string label, string context, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepCMAC.ExpandFeedbackMode(dkm, kdk, l, c, useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ExpandFeedbackMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int labelSize, int contextSize)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepCMAC.ExpandFeedbackMode(dkm, kdk, l, c));
    }

    [TestMethod]
    [DynamicData(nameof(DoublePipelineModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandDoublePipelineMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string label, string context, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepCMAC.ExpandDoublePipelineMode(dkm, kdk, l, c, useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ExpandDoublePipelineMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int labelSize, int contextSize)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepCMAC.ExpandDoublePipelineMode(dkm, kdk, l, c));
    }
}
