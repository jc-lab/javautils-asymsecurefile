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

public class DefaultHeaderChunk {
    private OperationType operationType = null;

    public DefaultHeaderChunk() {
    }

    public DefaultHeaderChunk(Chunk chunk) throws InvalidFileException {
        if(chunk == null)
            throw new InvalidFileException("Not exists DefaultHeader");
        if(chunk.getDataSize() < 1) {
            throw new InvalidFileException("Invalid DefaultHeader");
        }
        for(OperationType item : OperationType.values()) {
            if(item.value() == chunk.getData()[0]) {
                this.operationType = item;
            }
        }
        if(this.operationType == null) {
            throw new InvalidFileException("Invalid DefaultHeader");
        }
    }

    public Chunk build() {
        byte[] data = new byte[1];
        data[0] = this.operationType.value();
        return new Chunk(Jasf3ChunkType.DEFAULT_HEADER.value(), data);
    }

    public OperationType operationType() {
        return operationType;
    }
    public DefaultHeaderChunk operationType(OperationType operationType) {
        this.operationType = operationType;
        return this;
    }
}
