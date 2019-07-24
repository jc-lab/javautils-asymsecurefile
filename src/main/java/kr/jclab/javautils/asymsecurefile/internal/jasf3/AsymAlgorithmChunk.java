/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.AsymAlgorithm;
import kr.jclab.javautils.asymsecurefile.Chunk;
import kr.jclab.javautils.asymsecurefile.InvalidFileException;
import kr.jclab.javautils.asymsecurefile.internal.AlgorithmInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class AsymAlgorithmChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.ASYM_ALGORITHM;
    private final AlgorithmInfo algorithmInfo;

    /**
     * Gernerated chunk data
     *
     * @param algorithmInfo
     * @param data
     */
    private AsymAlgorithmChunk(AlgorithmInfo algorithmInfo, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.algorithmInfo = algorithmInfo;
    }

    /**
     * Parse chunk data
     *
     * @param dataSize
     * @param data
     * @throws InvalidFileException
     */
    public AsymAlgorithmChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);
        AlgorithmInfo algorithmInfo = null;

        try {
            ByteBuffer buffer = ByteBuffer.wrap(data, 0, dataSize).order(ByteOrder.LITTLE_ENDIAN);
            byte keyType = buffer.get();
            int keySize = buffer.getInt();
            byte[] asn1Oid = new byte[buffer.remaining()];
            buffer.get(asn1Oid);
            for (AsymAlgorithm item : AsymAlgorithm.values()) {
                if (item.getKeyType() == keyType) {
                    try {
                        ASN1Primitive primitive = ASN1ObjectIdentifier.fromByteArray(asn1Oid);
                        ASN1ObjectIdentifier asymAlgoOid = (primitive instanceof ASN1ObjectIdentifier) ? ((ASN1ObjectIdentifier) primitive) : null;
                        if (asymAlgoOid == null) {
                            throw new IOException("ERROR");
                        }
                        algorithmInfo = new AlgorithmInfo(item, keySize, asymAlgoOid);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    break;
                }
            }
        }catch (BufferUnderflowException e) {
            throw new InvalidFileException(e);
        }

        this.algorithmInfo = algorithmInfo;
    }

    public AlgorithmInfo algorithmInfo() {
        return this.algorithmInfo;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private AlgorithmInfo algorithmInfo;

        public Builder withAlgorithmInfo(AlgorithmInfo algorithmInfo) {
            this.algorithmInfo = algorithmInfo;
            return this;
        }

        public Chunk build() throws IOException {
            byte[] asn1Oid = algorithmInfo.getOid().getEncoded();
            ByteBuffer buffer = ByteBuffer.allocate(5 + asn1Oid.length).order(ByteOrder.LITTLE_ENDIAN);
            buffer.put(this.algorithmInfo.getAlgorithm().getKeyType());
            buffer.putInt(this.algorithmInfo.getKeySize());
            buffer.put(asn1Oid);
            buffer.flip();
            return new AsymAlgorithmChunk(algorithmInfo, buffer.array());
        }
    }
}
