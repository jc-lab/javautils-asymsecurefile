/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;
import kr.jclab.javautils.asymsecurefile.DataAlgorithm;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.Arrays;

public class DataAlgorithmChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.DATA_ALGORITHM;
    private final DataAlgorithm dataAlgorithm;

    /**
     * Generated chunk data
     *
     * @param dataAlgorithm
     * @param data
     */
    private DataAlgorithmChunk(DataAlgorithm dataAlgorithm, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.dataAlgorithm = dataAlgorithm;
    }

    /**
     * Parse chunk data
     *
     * @param dataSize
     * @param data
     * @throws InvalidFileException
     */
    public DataAlgorithmChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);

        DataAlgorithm dataAlgorithm = null;

        byte[] buffer = data;
        if(buffer.length != dataSize)
            buffer = Arrays.copyOf(data, dataSize);

        ASN1Primitive primitive = null;
        try {
            primitive = ASN1ObjectIdentifier.fromByteArray(buffer);
        } catch (IOException e) {
            throw new InvalidFileException(e);
        }
        ASN1ObjectIdentifier asymAlgoOid = (primitive instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)primitive) : null;
        if(asymAlgoOid == null) {
            throw new InvalidFileException("ERROR");
        }
        for(DataAlgorithm item : DataAlgorithm.values()) {
            if(item.getIdentifier().equals(asymAlgoOid)) {
                dataAlgorithm = item;
                break;
            }
        }

        this.dataAlgorithm = dataAlgorithm;

        if(dataAlgorithm == null) {
            throw new InvalidFileException("Unknown DataAlgorithm");
        }
    }

    public DataAlgorithm dataAlgorithm() {
        return this.dataAlgorithm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private DataAlgorithm dataAlgorithm;

        public Builder withDataAlgorithm(DataAlgorithm dataAlgorithm) {
            this.dataAlgorithm = dataAlgorithm;
            return this;
        }

        public DataAlgorithmChunk build() throws IOException {
            return new DataAlgorithmChunk(this.dataAlgorithm, dataAlgorithm.getIdentifier().getEncoded());
        }
    }
}
