using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace NISTKeyDerivationDotNet;

public static class TwoStepCMAC
{
    public const int KeyDerivationKeySize = TagSize;
    private const int TagSize = 16;

    public static void Extract(Span<byte> keyDerivationKey, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> salt, CmacVariant cmacVariant)
    {
        if (keyDerivationKey.Length != KeyDerivationKeySize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {KeyDerivationKeySize} bytes long."); }
        if (sharedSecret.Length == 0) { throw new ArgumentOutOfRangeException(nameof(sharedSecret), sharedSecret.Length, $"{nameof(sharedSecret)} must be greater than 0 bytes long."); }
        if (salt.Length != (int)cmacVariant) { throw new ArgumentOutOfRangeException(nameof(salt), salt.Length, $"{nameof(salt)} must be {(int)cmacVariant} bytes long."); }

        var cmac = new CMac(new AesEngine(), TagSize * 8);
        cmac.Init(new KeyParameter(salt));
        cmac.BlockUpdate(sharedSecret);
        cmac.DoFinal(keyDerivationKey);
    }

    public static void ExpandCounterMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, bool useSeparator = true, bool encodeLength = true)
    {
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != KeyDerivationKeySize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {KeyDerivationKeySize} bytes long."); }

        Span<byte> result = new byte[derivedKeyingMaterial.Length];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4], keyControlMitigation = stackalloc byte[TagSize];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);
        int n = (derivedKeyingMaterial.Length + TagSize - 1) / TagSize;

        var cmac = new CMac(new AesEngine(), TagSize * 8);
        cmac.Init(new KeyParameter(keyDerivationKey));
        cmac.BlockUpdate(label);
        cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
        cmac.BlockUpdate(context);
        cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
        cmac.DoFinal(keyControlMitigation);

        for (int i = 0; i < n; i++) {
            IncrementBigEndian(counter);
            cmac.BlockUpdate(counter);
            cmac.BlockUpdate(label);
            cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
            cmac.BlockUpdate(context);
            cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
            cmac.BlockUpdate(keyControlMitigation);
            cmac.DoFinal(result.Slice(i * TagSize, TagSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
        CryptographicOperations.ZeroMemory(keyControlMitigation);
    }

    public static void ExpandFeedbackMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, bool useSeparator = true, bool encodeLength = true)
    {
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != KeyDerivationKeySize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {KeyDerivationKeySize} bytes long."); }

        Span<byte> result = new byte[derivedKeyingMaterial.Length];
        Span<byte> counter = stackalloc byte[4], iv = stackalloc byte[TagSize];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);
        int n = (derivedKeyingMaterial.Length + TagSize - 1) / TagSize;

        var cmac = new CMac(new AesEngine(), TagSize * 8);
        cmac.Init(new KeyParameter(keyDerivationKey));
        cmac.BlockUpdate(label);
        cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
        cmac.BlockUpdate(context);
        cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
        cmac.DoFinal(iv);

        for (int i = 0; i < n; i++) {
            cmac.BlockUpdate(i == 0 ? iv : result.Slice((i - 1) * TagSize, TagSize));
            IncrementBigEndian(counter);
            cmac.BlockUpdate(counter);
            cmac.BlockUpdate(label);
            cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
            cmac.BlockUpdate(context);
            cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
            cmac.DoFinal(result.Slice(i * TagSize, TagSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
    }

    public static void ExpandDoublePipelineMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, bool useSeparator = true, bool encodeLength = true)
    {
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != KeyDerivationKeySize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {KeyDerivationKeySize} bytes long."); }

        Span<byte> result = new byte[derivedKeyingMaterial.Length], firstPipeline = stackalloc byte[TagSize];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);
        int n = (derivedKeyingMaterial.Length + TagSize - 1) / TagSize;

        var cmac = new CMac(new AesEngine(), TagSize * 8);
        cmac.Init(new KeyParameter(keyDerivationKey));
        cmac.BlockUpdate(label);
        cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
        cmac.BlockUpdate(context);
        cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
        for (int i = 0; i < n; i++) {
            cmac.BlockUpdate(i == 0 ? Span<byte>.Empty : firstPipeline);
            cmac.DoFinal(firstPipeline);

            cmac.BlockUpdate(firstPipeline);
            IncrementBigEndian(counter);
            cmac.BlockUpdate(counter);
            cmac.BlockUpdate(label);
            cmac.BlockUpdate(useSeparator ? separator : Span<byte>.Empty);
            cmac.BlockUpdate(context);
            cmac.BlockUpdate(encodeLength ? length : Span<byte>.Empty);
            cmac.DoFinal(result.Slice(i * TagSize, TagSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
        CryptographicOperations.ZeroMemory(firstPipeline);
    }

    private static void IncrementBigEndian(Span<byte> counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) { break; }
        }
    }
}
