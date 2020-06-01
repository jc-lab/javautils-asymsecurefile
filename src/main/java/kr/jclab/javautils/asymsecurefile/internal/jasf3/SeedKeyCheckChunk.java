/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;
import kr.jclab.javautils.asymsecurefile.internal.utils.Pbkdf2Utils;

import javax.crypto.spec.SecretKeySpec;
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
        Pbkdf2Utils.generateKey(new SecretKeySpec(plainkey, "HmacSHA256"), this.salt, 1000, PASS_SIZE, computed);
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
            Pbkdf2Utils.generateKey(new SecretKeySpec(plainkey, "HmacSHA256"), this.salt, 1000, PASS_SIZE, this.encoded);
            return this;
        }

        public SeedKeyCheckChunk build() {
            byte[] payload = new byte[this.salt.length + this.encoded.length];
            System.arraycopy(this.salt, 0, payload, 0, this.salt.length);
            System.arraycopy(this.encoded, 0, payload, this.salt.length, this.encoded.length);
            return new SeedKeyCheckChunk((short)payload.length, payload);
        }
    }
}
