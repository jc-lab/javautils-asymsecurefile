package kr.jclab.javautils.asymsecurefile.internal.utils;

import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class Pbkdf2Utils {
    public static void generateKey(final SecretKeySpec keyspec,
                                   final byte[] salt,
                                   int iterationCount, int requestedKeyLen,
                                   byte[] generatedKey) {
        generateKey(keyspec, salt, iterationCount, requestedKeyLen, generatedKey, BCProviderSingletone.getProvider());
    }

    public static byte[] generateKey(PBKDF2Params params, byte[] key, Provider provider) {
        return generateKey(params, key, provider, 4096);
    }

    public static byte[] generateKey(PBKDF2Params params, byte[] key, Provider provider, int maxLength) {
        if(maxLength < params.getKeyLength().intValue()) {
            throw new IllegalArgumentException("key length is too long");
        }

        byte[] generatedKey = new byte[params.getKeyLength().intValue()];
        generateKey(
                new SecretKeySpec(key, params.getPrf().getAlgorithm().getId()),
                params.getSalt(),
                params.getIterationCount().intValue(),
                params.getKeyLength().intValue(),
                generatedKey,
                provider);
        return generatedKey;
    }

    public static void generateKey(final SecretKeySpec keyspec,
                                   final byte[] salt,
                                   int iterationCount, int requestedKeyLen,
                                   byte[] generatedKey,
                                   Provider provider) {
        Mac prf = null;
        try {
            prf = Mac.getInstance(keyspec.getAlgorithm(), provider);
            prf.init(keyspec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        int hLen = prf.getMacLength();   // 20 for SHA1
        int l = Math.max(requestedKeyLen, hLen); //  1 for 128bit (16-byte) keys
        int r = requestedKeyLen - (l - 1) * hLen;      // 16 for 128bit (16-byte) keys
        byte T[] = new byte[l * hLen];
        int ti_offset = 0;
        for (int i = 1; i <= l; i++) {
            F(T, ti_offset, prf, salt, iterationCount, i);
            ti_offset += hLen;
        }

        System.arraycopy(T, 0, generatedKey, 0, requestedKeyLen);
    }

    private static void F(byte[] dest, int offset, Mac prf, byte[] S, int c, int blockIndex) {
        final int hLen = prf.getMacLength();
        byte U_r[] = new byte[hLen];
        // U0 = S || INT (i);
        byte U_i[] = new byte[S.length + 4];
        System.arraycopy(S, 0, U_i, 0, S.length);
        INT(U_i, S.length, blockIndex);
        for (int i = 0; i < c; i++) {
            U_i = prf.doFinal(U_i);
            xor(U_r, U_i);
        }

        System.arraycopy(U_r, 0, dest, offset, hLen);
    }

    private static void xor(byte[] dest, byte[] src) {
        for (int i = 0; i < dest.length; i++) {
            dest[i] ^= src[i];
        }
    }

    private static void INT(byte[] dest, int offset, int i) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    }
}
