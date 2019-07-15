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
import kr.jclab.javautils.asymsecurefile.internal.AlgorithmInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.Arrays;

public class AsymAlgorithmChunk {
    private AlgorithmInfo algorithmInfo = null;

    public AsymAlgorithmChunk() {
    }

    public AsymAlgorithmChunk(Chunk chunk) throws InvalidFileException {
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
            this.algorithmInfo = new AlgorithmInfo(asymAlgoOid);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Chunk build() throws IOException {
        return new Chunk(Jasf3ChunkType.ASYM_ALGORITHM.value(), algorithmInfo.getOid().getEncoded());
    }

    public AlgorithmInfo algorithmInfo() {
        return this.algorithmInfo;
    }
    public AsymAlgorithmChunk algorithmInfo(AlgorithmInfo algorithmInfo) {
        this.algorithmInfo = algorithmInfo;
        return this;
    }
}
