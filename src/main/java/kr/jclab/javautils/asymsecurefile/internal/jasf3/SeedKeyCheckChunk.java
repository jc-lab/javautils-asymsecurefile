/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.Chunk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class SeedKeyCheckChunk extends Chunk {
    private static final int SALT_SIZE = 16;
    private static final int PASS_SIZE = 16;
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.SEED_KEY_CHECK;
    private final byte[] salt;
    private final byte[] encoded;

    public SeedKeyCheckChunk(Short dataSize, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.salt = Arrays.copyOfRange(data, 0, SALT_SIZE);
        this.encoded = Arrays.copyOfRange(data, SALT_SIZE, SALT_SIZE + PASS_SIZE);
    }

    public final byte[] getEncoded() {
        return this.encoded;
    }

    public final boolean verify(byte[] plainkey) {
        byte[] computed = new byte[PASS_SIZE];
        Pbkdf2.GenerateKey(plainkey, this.salt, 1000, PASS_SIZE, computed);
        return Arrays.equals(computed, this.encoded);
    }

    public static final Builder builder(Random random) {
        return new Builder(random);
    }

    public static final class Builder {
        private Random random;
        private byte[] salt;
        private byte[] encoded;

        public Builder(Random random) {
            this.random = random;
            this.salt = new byte[SALT_SIZE];
            this.random.nextBytes(this.salt);
        }

        public Builder withPlainKey(byte[] plainkey) {
            this.encoded = new byte[PASS_SIZE];
            Pbkdf2.GenerateKey(plainkey, this.salt, 1000, PASS_SIZE, this.encoded);
            return this;
        }

        public SeedKeyCheckChunk build() {
            byte[] payload = new byte[this.salt.length + this.encoded.length];
            System.arraycopy(this.salt, 0, payload, 0, this.salt.length);
            System.arraycopy(this.encoded, 0, payload, this.salt.length, this.encoded.length);
            return new SeedKeyCheckChunk((short)payload.length, payload);
        }
    }

    public final static class Pbkdf2 {
        public static void GenerateKey(final byte[] masterPassword,
                                       final byte[] salt,
                                       int iterationCount, int requestedKeyLen,
                                       byte[] generatedKey) {

            SecretKeySpec keyspec = new SecretKeySpec(masterPassword, "HmacSHA256");
            Mac prf = null;
            try {
                prf = Mac.getInstance(keyspec.getAlgorithm());
                prf.init(keyspec);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
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
}
