/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.Chunk;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;
import kr.jclab.javautils.asymsecurefile.OperationType;

public class DefaultHeaderChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.DEFAULT_HEADER;
    private final OperationType operationType;

    public DefaultHeaderChunk(OperationType operationType, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.operationType = operationType;
    }

    public DefaultHeaderChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);
        OperationType operationType = null;
        for(OperationType item : OperationType.values()) {
            if(item.value() == data[0]) {
                operationType = item;
            }
        }
        this.operationType = operationType;
        if(operationType == null) {
            throw new InvalidFileException("Invalid DefaultHeader");
        }
    }

    public OperationType operationType() {
        return operationType;
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

        public DefaultHeaderChunk build() {
            return new DefaultHeaderChunk(this.operationType, new byte[] {this.operationType.value()});
        }
    }
}
