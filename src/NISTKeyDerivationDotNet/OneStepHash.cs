using System.Security.Cryptography;

namespace NISTKeyDerivationDotNet;

public static class OneStepHash
{
    public static void DeriveKey(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> fixedInfo, HashAlgorithmName hashAlgorithmName)
    {
        int hashSize = GetHashSize(hashAlgorithmName);
        if (hashSize == 0) { throw new NotSupportedException("The specified hash function is not supported."); }
        if (derivedKeyingMaterial.Length == 0) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be greater than 0 bytes long."); }
        if (sharedSecret.Length == 0) { throw new ArgumentOutOfRangeException(nameof(sharedSecret), sharedSecret.Length, $"{nameof(sharedSecret)} must be greater than 0 bytes long."); }

        int reps = (derivedKeyingMaterial.Length + hashSize - 1) / hashSize;
        Span<byte> result = new byte[reps * hashSize];
        Span<byte> counter = stackalloc byte[4];
        counter.Clear();
        using var hash = IncrementalHash.CreateHash(hashAlgorithmName);
        for (int i = 0; i < reps; i++) {
            IncrementBigEndian(counter);
            hash.AppendData(counter);
            hash.AppendData(sharedSecret);
            hash.AppendData(fixedInfo);
            hash.GetHashAndReset(result.Slice(i * hashSize, hashSize));
        }
        result[..derivedKeyingMaterial.Length].CopyTo(derivedKeyingMaterial);
        CryptographicOperations.ZeroMemory(result);
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
