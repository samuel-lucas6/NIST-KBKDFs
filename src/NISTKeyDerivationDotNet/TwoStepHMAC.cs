using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NISTKeyDerivationDotNet;

public static class TwoStepHMAC
{
    public static void Extract(Span<byte> keyDerivationKey, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> salt, HashAlgorithmName hashAlgorithmName)
    {
        int hashSize = GetHashSize(hashAlgorithmName);
        if (hashSize == 0) { throw new NotSupportedException("The specified hash function is not supported."); }
        if (keyDerivationKey.Length != hashSize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {hashSize} bytes long."); }
        if (sharedSecret.Length == 0) { throw new ArgumentOutOfRangeException(nameof(sharedSecret), sharedSecret.Length, $"{nameof(sharedSecret)} must be greater than 0 bytes long."); }

        using var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, salt);
        hmac.AppendData(sharedSecret);
        hmac.GetCurrentHash(keyDerivationKey);
    }

    public static void ExpandCounterMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, HashAlgorithmName hashAlgorithmName, bool useSeparator = true, bool encodeLength = true)
    {
        int hashSize = GetHashSize(hashAlgorithmName);
        if (hashSize == 0) { throw new NotSupportedException("The specified hash function is not supported."); }
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != hashSize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {hashSize} bytes long."); }

        int n = (derivedKeyingMaterial.Length + hashSize - 1) / hashSize;
        Span<byte> result = new byte[n * hashSize];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);
        using var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, keyDerivationKey);
        for (int i = 0; i < n; i++) {
            IncrementBigEndian(counter);
            hmac.AppendData(counter);
            hmac.AppendData(label);
            hmac.AppendData(useSeparator ? separator : Span<byte>.Empty);
            hmac.AppendData(context);
            hmac.AppendData(encodeLength ? length : Span<byte>.Empty);
            hmac.GetHashAndReset(result.Slice(i * hashSize, hashSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
    }

    public static void ExpandFeedbackMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, HashAlgorithmName hashAlgorithmName, bool useSeparator = true, bool encodeLength = true)
    {
        int hashSize = GetHashSize(hashAlgorithmName);
        if (hashSize == 0) { throw new NotSupportedException("The specified hash function is not supported."); }
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != hashSize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {hashSize} bytes long."); }

        int n = (derivedKeyingMaterial.Length + hashSize - 1) / hashSize;
        Span<byte> result = new byte[n * hashSize];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);
        using var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, keyDerivationKey);
        for (int i = 0; i < n; i++) {
            hmac.AppendData(i == 0 ? iv : result.Slice((i - 1) * hashSize, hashSize));
            IncrementBigEndian(counter);
            hmac.AppendData(counter);
            hmac.AppendData(label);
            hmac.AppendData(useSeparator ? separator : Span<byte>.Empty);
            hmac.AppendData(context);
            hmac.AppendData(encodeLength ? length : Span<byte>.Empty);
            hmac.GetHashAndReset(result.Slice(i * hashSize, hashSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
    }

    public static void ExpandDoublePipelineMode(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, HashAlgorithmName hashAlgorithmName, bool useSeparator = true, bool encodeLength = true)
    {
        int hashSize = GetHashSize(hashAlgorithmName);
        if (hashSize == 0) { throw new NotSupportedException("The specified hash function is not supported."); }
        if (derivedKeyingMaterial.Length == 0 || derivedKeyingMaterial.Length > uint.MaxValue / 8) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be between 1 and {uint.MaxValue / 8} bytes long."); }
        if (keyDerivationKey.Length != hashSize) { throw new ArgumentOutOfRangeException(nameof(keyDerivationKey), keyDerivationKey.Length, $"{nameof(keyDerivationKey)} must be {hashSize} bytes long."); }

        int n = (derivedKeyingMaterial.Length + hashSize - 1) / hashSize;
        Span<byte> result = new byte[n * hashSize], firstPipeline = stackalloc byte[hashSize];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        Span<byte> separator = stackalloc byte[] { 0x00 }, length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)derivedKeyingMaterial.Length * 8);

        using var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, keyDerivationKey);
        hmac.AppendData(label);
        hmac.AppendData(useSeparator ? separator : Span<byte>.Empty);
        hmac.AppendData(context);
        hmac.AppendData(encodeLength ? length : Span<byte>.Empty);
        for (int i = 0; i < n; i++) {
            hmac.AppendData(i == 0 ? Span<byte>.Empty : firstPipeline);
            hmac.GetHashAndReset(firstPipeline);

            hmac.AppendData(firstPipeline);
            IncrementBigEndian(counter);
            hmac.AppendData(counter);
            hmac.AppendData(label);
            hmac.AppendData(useSeparator ? separator : Span<byte>.Empty);
            hmac.AppendData(context);
            hmac.AppendData(encodeLength ? length : Span<byte>.Empty);
            hmac.GetHashAndReset(result.Slice(i * hashSize, hashSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
        CryptographicOperations.ZeroMemory(firstPipeline);
    }

    private static int GetHashSize(HashAlgorithmName hashAlgorithmName)
    {
        if (hashAlgorithmName == HashAlgorithmName.SHA256 || hashAlgorithmName == HashAlgorithmName.SHA3_256) { return SHA256.HashSizeInBytes; }
        if (hashAlgorithmName == HashAlgorithmName.SHA384 || hashAlgorithmName == HashAlgorithmName.SHA3_384) { return SHA384.HashSizeInBytes; }
        return hashAlgorithmName == HashAlgorithmName.SHA512 || hashAlgorithmName == HashAlgorithmName.SHA3_512 ? SHA512.HashSizeInBytes : 0;
    }

    private static void IncrementBigEndian(Span<byte> counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) { break; }
        }
    }
}
