using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace NISTKeyDerivationDotNet;

public static class OneStepKMAC
{
    public static void DeriveKey(Span<byte> derivedKeyingMaterial, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> fixedInfo, KmacVariant kmacVariant)
    {
        if (derivedKeyingMaterial.Length == 0) { throw new ArgumentOutOfRangeException(nameof(derivedKeyingMaterial), derivedKeyingMaterial.Length, $"{nameof(derivedKeyingMaterial)} must be greater than 0 bytes long."); }
        if (sharedSecret.Length == 0) { throw new ArgumentOutOfRangeException(nameof(sharedSecret), sharedSecret.Length, $"{nameof(sharedSecret)} must be greater than 0 bytes long."); }

        Span<byte> counter = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, 1);
        var kmac = new KMac((int)kmacVariant, "KDF"u8.ToArray());
        var parameters = new KeyParameter(salt.Length == 0 ? (int)kmacVariant == 128 ? new byte[164] : new byte[132] : salt);
        kmac.Init(parameters);
        kmac.BlockUpdate(counter);
        kmac.BlockUpdate(sharedSecret);
        kmac.BlockUpdate(fixedInfo);
        kmac.OutputFinal(derivedKeyingMaterial);
    }
}
