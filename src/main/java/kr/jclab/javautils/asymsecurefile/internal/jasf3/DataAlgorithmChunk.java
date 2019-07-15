/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.Chunk;
import kr.jclab.javautils.asymsecurefile.DataAlgorithm;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.Arrays;

public class DataAlgorithmChunk {
    private DataAlgorithm dataAlgorithm = null;

    public DataAlgorithmChunk() {
    }

    public DataAlgorithmChunk(Chunk chunk) throws InvalidFileException {
        byte[] data;

        if(chunk == null)
            throw new InvalidFileException("Not exists AsymAlgorithm");

        data = chunk.getData();
        if(data.length != chunk.getDataSize()) {
            data = Arrays.copyOf(data, chunk.getDataSize());
        }

        try {
            ASN1Primitive primitive = ASN1ObjectIdentifier.fromByteArray(data);
            ASN1ObjectIdentifier asymAlgoOid = (primitive instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier)primitive) : null;
            if(asymAlgoOid == null) {
                throw new IOException("ERROR");
            }
            for(DataAlgorithm dataAlgorithm : DataAlgorithm.values()) {
                if(dataAlgorithm.getIdentifier().equals(asymAlgoOid)) {
                    this.dataAlgorithm = dataAlgorithm;
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(this.dataAlgorithm == null) {
            throw new InvalidFileException("Unknown DataAlgorithm");
        }
    }

    public Chunk build() throws IOException {
        return new Chunk(Jasf3ChunkType.DATA_ALGORITHM.value(), dataAlgorithm.getIdentifier().getEncoded());
    }

    public DataAlgorithm dataAlgorithm() {
        return this.dataAlgorithm;
    }
    public DataAlgorithmChunk dataAlgorithm(DataAlgorithm dataAlgorithm) {
        this.dataAlgorithm = dataAlgorithm;
        return this;
    }
}
