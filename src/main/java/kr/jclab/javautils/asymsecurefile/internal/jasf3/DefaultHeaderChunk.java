/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;
import kr.jclab.javautils.asymsecurefile.OperationType;

import java.util.Arrays;
import java.util.Random;

public class DefaultHeaderChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.DEFAULT_HEADER;
    private final OperationType operationType;
    private final byte[] seed = new byte[16];

    public DefaultHeaderChunk(OperationType operationType, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.operationType = operationType;
        System.arraycopy(data, 0, seed, 0, 16);
    }

    public DefaultHeaderChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);
        OperationType operationType = null;
        if(dataSize < 16) {
            throw new InvalidFileException("Invalid ASN1DefaultHeaderObject");
        }
        for(OperationType item : OperationType.values()) {
            if(item.value() == data[0]) {
                operationType = item;
            }
        }
        this.operationType = operationType;
        System.arraycopy(data, 0, seed, 0, 16);
        if(operationType == null) {
            throw new InvalidFileException("Invalid ASN1DefaultHeaderObject");
        }
    }

    public OperationType operationType() {
        return operationType;
    }

    public byte[] seed() {
        return Arrays.copyOf(this.seed, 16);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private OperationType operationType;

        public Builder withOperationType(OperationType operationType) {
            this.operationType = operationType;
            return this;
        }

        public DefaultHeaderChunk build(Random secureRandom) {
            byte[] seed = new byte[16];
            secureRandom.nextBytes(seed);
            seed[0] = this.operationType.value();
            return new DefaultHeaderChunk(this.operationType, seed);
        }
    }
}
