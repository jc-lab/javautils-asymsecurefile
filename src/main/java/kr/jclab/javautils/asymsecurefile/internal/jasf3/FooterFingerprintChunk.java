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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class FooterFingerprintChunk {
    /*
     * 0x01 FINGER_PRINT_SIZE(2byte, little endian)
     * FINGER_PRINT
     * 0x02 FINGER_PRINT_SIZE(2byte, little endian)
     * SIGNATURE
     * 0x00
     * FooterFingerprintChunk SIZE (2byte)
     * TOTAL_FILE_SIZE (8bytes, little endian)
     */
    private byte[] fingerprint = null;
    private byte[] signature = null;
    private short footerSize = 0;
    private long totalFileSize = 0;
    private long totalFileSizeWithoutFooter = 0;

    public FooterFingerprintChunk() {
    }

    public FooterFingerprintChunk(Chunk chunk) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.wrap(chunk.getData(), 0, chunk.getDataSize()).order(ByteOrder.LITTLE_ENDIAN);
        byte type;

        if(chunk == null)
            throw new InvalidFileException("Not exists FooterFingerprint");

        do {
            type = byteBuffer.get();
            if(type > 0) {
                short size = byteBuffer.getShort();
                switch(type) {
                    case 0x01:
                        this.fingerprint = new byte[size];
                        byteBuffer.get(this.fingerprint, 0, size);
                        break;
                    case 0x02:
                        this.signature = new byte[size];
                        byteBuffer.get(this.signature, 0, size);
                        break;
                }
            }
        } while (type > 0);
        this.footerSize = byteBuffer.getShort();
        this.totalFileSize = byteBuffer.getLong();
    }

    public Chunk build() {
        int needSize = ((this.fingerprint != null) ? this.fingerprint.length + 3 : 0) + ((this.signature != null) ? this.signature.length + 3 : 0);
        ByteBuffer byteBuffer = ByteBuffer.allocate(11 + needSize).order(ByteOrder.LITTLE_ENDIAN);

        this.totalFileSize = totalFileSizeWithoutFooter + byteBuffer.capacity() + 3;

        if(this.fingerprint != null) {
            byteBuffer.put((byte)0x01);
            byteBuffer.putShort((short)this.fingerprint.length);
            byteBuffer.put(this.fingerprint);
        }
        if(this.signature != null) {
            byteBuffer.put((byte)0x02);
            byteBuffer.putShort((short)this.signature.length);
            byteBuffer.put(this.signature);
        }
        byteBuffer.put((byte)0);
        byteBuffer.putShort(this.footerSize);
        byteBuffer.putLong(this.totalFileSize);
        byteBuffer.flip();
        return new Chunk(Jasf3ChunkType.FOOTER_FINGERPRINT.value(), byteBuffer.array());
    }

    public byte[] fingerprint() {
        return fingerprint;
    }

    public FooterFingerprintChunk fingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
        return this;
    }

    public byte[] signature() {
        return signature;
    }

    public FooterFingerprintChunk signature(byte[] signature) {
        this.signature = signature;
        return this;
    }

    public short footerSize() {
        return footerSize;
    }

    public FooterFingerprintChunk footerSize(short footerSize) {
        this.footerSize = footerSize;
        return this;
    }

    public long totalFileSize() {
        return totalFileSize;
    }

    public FooterFingerprintChunk totalFileSizeWithoutFooter(long totalFileSizeWithoutFooter) {
        this.totalFileSizeWithoutFooter = totalFileSizeWithoutFooter;
        return this;
    }
}
