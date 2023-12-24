namespace NISTKeyDerivationDotNet.Tests;

[TestClass]
public class TwoStepHMACTests
{
    // https://www.rfc-editor.org/rfc/rfc5869#appendix-A
    public static IEnumerable<object[]> ExtractTestVectors()
    {
        yield return
        [
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "SHA256"
        ];
        yield return
        [
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "SHA256"
        ];
        yield return
        [
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "SHA256"
        ];
    }

    // https://github.com/canonical/go-sp800.108-kdf/blob/main/kdf_test.go#L782
    public static IEnumerable<object[]> CounterModeTestVectors()
    {
        yield return
        [
            "10621342bfb0fd40046c0e29f2cfdbf0",
            "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0",
            "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779",
            "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6",
            "7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "dabcffa16a7589deee6c768aaf01e0813de909005526da54700083ef068f854d49941279689a1726",
            "1d9209183e557d3aac7e2ab53d26ec659df2a745fe56a53818ef5853a42ce194",
            "",
            "c01a431a32833930a22abee5c6ea34db459316def3b241529ece7e39e2069a1e6b942946132eebc9679801d2cefef4bbb6a1b84ef853325b7bc498fd",
            "SHA256",
            false,
            false
        ];
    }

    // https://github.com/canonical/go-sp800.108-kdf/blob/main/kdf_test.go#L4702
    // https://github.com/canonical/go-sp800.108-kdf/blob/main/kdf_test.go#L6776
    public static IEnumerable<object[]> FeedbackModeTestVectors()
    {
        yield return
        [
            "bd1476f43a4e315747cf5918e0ea5bc0d98769457477c3ab18b742def0e079a933b756365afb5541f253fee43c6fd788a44041038509e9eeb68f7d65ffbb5f95",
            "93f698e842eed75394d629d957e2e89c6e741f810b623c8b901e38376d068e7b",
            "9f575d9059d3e0c0803f08112f8a806de3c3471912cdf42b095388b14b33508e",
            "53b89c18690e2057a1d167822e636de50be0018532c431f7f5e37f77139220d5e042599ebe266af5767ee18cd2c5c19a1f0f80",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "0aa2002a47da3d5f840bbb4fdc7fec52583a3d9734d8f69f76983803f10ec2872ad88baec5234e30f84022dcec260072a65047ad6ea7bb0646c71012b8684c0d7a0bd018ed4e23a289640a0d9c7c1885d310d933fd3fab5a20b1667da6e403a23909fac35bc1e80b7b82de2ed8b105a1a34a9754a954f95353d7c2f00a6beefed72ab38a7b638304c1b712027cd16d3dc9735db2fcb2f05712b490080c0feb94827bda60f0f47eb449eafb85380187e6df31c2f0660027f086ea5b5965e4d705ae7db9959a8e87acdcde604039a0fbfa72274b8339cdb3d53f432229125d20f3800db4351b4754742b2d6426a8e24076f349c589409feb45ff65738fd3d77168",
            "a5eb2ebcb9cc7aa0ee9f38cdcc18956a041714369acbcb722d995010f2b8463d",
            "11be2ef7753959c3c070d49afce9c4d09ad8311a14e03bcf9edc2c11fe6950b4",
            "8f71ffd48fe4680cb13582f5c977c99fd6c4aa8012378857989b52fbee90d358df1e58802db0a31f562d064a9c42cb44136ee9",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "17e16518944cffc2c4ae33ab0486d63d88f5e0098bc0f5851a68c6d25d54b4c775dbc446ea3a774a5ba21ee11ffcd9268affe87b2d0001fd7d8f8bf68bb7592a",
            "c895d8c7b64c346ce75dd55602895e95997136309959c754bbc294b65f71b465",
            "",
            "541a3ca9d786283cc8fc6ea475d8d04204eeb76b7cd80e1b0ac676e9d39b5cc9f52ea8309f5ccac9a38d63ea2d598c564bde0a",
            "",
            "SHA256",
            false,
            false
        ];
    }

    // https://github.com/canonical/go-sp800.108-kdf/blob/main/kdf_test.go#L8662
    public static IEnumerable<object[]> DoublePipelineModeTestVectors()
    {
        yield return
        [
            "d69f74f518c9f64f90a0beebab69f689b73b5c13eb0f860a95cad7d9814f8c506eb7b179a5c5b4466a9ec154c3bf1c13efd6ec0d82b02c29af2c690299edc453",
            "02d36fa021c20ddbdee469f0579468bae5cb13b548b6c61cdf9d3ec419111de2",
            "85abe38bf265fbdc6445ae5c71159f1548c73b7d526a623104904a0f8792070b3df9902b9669490425a385eadb0f9c76e46f0f",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "4d515afd94a115e504ed265dbbe019f1405b4b7ab351e6d496b6b9c15ae7601905eaa123b80c9855fdd458f9871f7ec2d16e05bf8991f8165c9faf916d2c62bcfb34f0638a2f8c95a5b4b720123719988c5b6fd436858f3df65c4e22fec179cd065ea5cb8551c4582f65ff4f7eae9a3fda752ae862812016aa76343c5b6040d921f14f772d2fa9dba65094b244e770965629829dd14a9af537e80ca2122eb71e9b4b1c8e25dfe3b53155d969e596095675ca8dc67c12e11e7d950f219cad5e0bef3d6668becac52140b9c153897466331ddaedac6d0ae68672e99cae96f6a021686d4fc2f1c9febacf8bc9005e4afb9a5d24a15aa2d7afe1adcad43dc346b09d",
            "40da26dc85fc48a30a52fb7bc8d6db7dd18cb57eb0de5c9b210b5d574dde358b",
            "a166a4e1b63f753ae8f6850c7cf96ff8e83b22eced5dd458af592bb26e3a1d51c85eefc39accd2805095d3288d4b0d0cb996a1",
            "",
            "SHA256",
            false,
            false
        ];
        yield return
        [
            "a0a718541e7722e8a62b7946ea0244d1b6f3f1dc9213a880cc1c777ead8814b51b687777258e32fe9f0e85854271d9cb029026c3c7eb920136005634b4e1c09acffa969cd952",
            "9306645e6b3182a66b1cca905480b7ffa8d60467a52c12202476a54287a45bc0",
            "",
            "0fc1704af3daaa5942025495c22a710ed64bba03d71f0f89ee2b37552a073797d639a8fda73ee616332f5a54e51359ea578382",
            "SHA256",
            false,
            false
        ];
    }

    [TestMethod]
    [DynamicData(nameof(ExtractTestVectors), DynamicDataSourceType.Method)]
    public void Extract_Valid(string keyDerivationKey, string sharedSecret, string salt, string hashAlgorithmName)
    {
        Span<byte> kdk = stackalloc byte[keyDerivationKey.Length / 2];
        Span<byte> ss = Convert.FromHexString(sharedSecret);
        Span<byte> s = Convert.FromHexString(salt);

        TwoStepHMAC.Extract(kdk, ss, s, new HashAlgorithmName(hashAlgorithmName));

        Assert.AreEqual(keyDerivationKey, Convert.ToHexString(kdk).ToLower());
    }

    [TestMethod]
    [DataRow(SHA256.HashSizeInBytes + 1, 32, 32, "SHA256")]
    [DataRow(SHA256.HashSizeInBytes - 1, 32, 32, "SHA256")]
    [DataRow(SHA256.HashSizeInBytes, 0, 32, "SHA256")]
    [DataRow(MD5.HashSizeInBytes, 32, 32, "MD5")]
    [DataRow(SHA1.HashSizeInBytes, 32, 32, "SHA1")]
    public void Extract_Invalid(int keyDerivationKeySize, int sharedSecretSize, int saltSize, string hashAlgorithmName)
    {
        var kdk = new byte[keyDerivationKeySize];
        var ss = new byte[sharedSecretSize];
        var s = new byte[saltSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepHMAC.Extract(kdk, ss, s, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => TwoStepHMAC.Extract(kdk, ss, s, new HashAlgorithmName(hashAlgorithmName)));
        }
    }

    [TestMethod]
    [DynamicData(nameof(CounterModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandCounterMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string label, string context, string hashAlgorithmName, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepHMAC.ExpandCounterMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName), useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow((int)(uint.MaxValue / 8 + 1), SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes + 1, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes - 1, 16, 32, "SHA256")]
    [DataRow(32, MD5.HashSizeInBytes, 16, 32, "MD5")]
    [DataRow(32, SHA1.HashSizeInBytes, 16, 32, "SHA1")]
    public void ExpandCounterMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int labelSize, int contextSize, string hashAlgorithmName)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepHMAC.ExpandCounterMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => TwoStepHMAC.ExpandCounterMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
    }

    [TestMethod]
    [DynamicData(nameof(FeedbackModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandFeedbackMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string iv, string label, string context, string hashAlgorithmName, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> i = Convert.FromHexString(iv);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepHMAC.ExpandFeedbackMode(dkm, kdk, i, l, c, new HashAlgorithmName(hashAlgorithmName), useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, SHA256.HashSizeInBytes, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow((int)(uint.MaxValue / 8 + 1), SHA256.HashSizeInBytes, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes + 1, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes - 1, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow(32, MD5.HashSizeInBytes, MD5.HashSizeInBytes, 16, 32, "MD5")]
    [DataRow(32, SHA1.HashSizeInBytes, SHA1.HashSizeInBytes, 16, 32, "SHA1")]
    public void ExpandFeedbackMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int ivSize, int labelSize, int contextSize, string hashAlgorithmName)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var i = new byte[ivSize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepHMAC.ExpandFeedbackMode(dkm, kdk, i, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => TwoStepHMAC.ExpandFeedbackMode(dkm, kdk, i, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
    }

    [TestMethod]
    [DynamicData(nameof(DoublePipelineModeTestVectors), DynamicDataSourceType.Method)]
    public void ExpandDoublePipelineMode_Valid(string derivedKeyingMaterial, string keyDerivationKey, string label, string context, string hashAlgorithmName, bool useSeparator, bool encodeLength)
    {
        Span<byte> dkm = stackalloc byte[derivedKeyingMaterial.Length / 2];
        Span<byte> kdk = Convert.FromHexString(keyDerivationKey);
        Span<byte> l = Convert.FromHexString(label);
        Span<byte> c = Convert.FromHexString(context);

        TwoStepHMAC.ExpandDoublePipelineMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName), useSeparator, encodeLength);

        Assert.AreEqual(derivedKeyingMaterial, Convert.ToHexString(dkm).ToLower());
    }

    [TestMethod]
    [DataRow(0, SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow((int)(uint.MaxValue / 8 + 1), SHA256.HashSizeInBytes, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes + 1, 16, 32, "SHA256")]
    [DataRow(32, SHA256.HashSizeInBytes - 1, 16, 32, "SHA256")]
    [DataRow(32, MD5.HashSizeInBytes, 16, 32, "MD5")]
    [DataRow(32, SHA1.HashSizeInBytes, 16, 32, "SHA1")]
    public void ExpandDoublePipelineMode_Invalid(int derivedKeyingMaterialSize, int keyDerivationKeySize, int labelSize, int contextSize, string hashAlgorithmName)
    {
        var dkm = new byte[derivedKeyingMaterialSize];
        var kdk = new byte[keyDerivationKeySize];
        var l = new byte[labelSize];
        var c = new byte[contextSize];

        if (hashAlgorithmName is not ("MD5" or "SHA1")) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => TwoStepHMAC.ExpandDoublePipelineMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
        else {
            Assert.ThrowsException<NotSupportedException>(() => TwoStepHMAC.ExpandDoublePipelineMode(dkm, kdk, l, c, new HashAlgorithmName(hashAlgorithmName)));
        }
    }
}
