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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class FooterChunk extends Chunk {
    public static final Jasf3ChunkType CHUNK_TYPE = Jasf3ChunkType.FOOTER_FINGERPRINT;
    /*
     * 0x01 FINGER_PRINT_SIZE(2byte, little endian)
     * FINGER_PRINT
     * 0x02 FINGER_PRINT_SIZE(2byte, little endian)
     * SIGNATURE
     * 0x03 MAC_SIZE(2byte, little endian)
     * MAC
     * 0x00
     * FooterChunk SIZE (2byte)
     * TOTAL_FILE_SIZE (8bytes, little endian)
     */
    private final byte[] fingerprint;
    private final byte[] signature;
    private final byte[] mac;
    private final byte[] timestampToken;
    private final short footerSize;
    private final long totalFileSize;
    private final long totalFileSizeWithoutFooter;

    public FooterChunk(Short dataSize, byte[] data) throws InvalidFileException {
        super(CHUNK_TYPE.value(), (short)0, dataSize, data);
        byte[] fingerprint = null;
        byte[] signature = null;
        byte[] mac = null;
        byte[] timestampToken = null;

        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(data, 0, dataSize).order(ByteOrder.LITTLE_ENDIAN);
            byte type;

            do {
                type = byteBuffer.get();
                if (type > 0) {
                    short size = byteBuffer.getShort();
                    switch (type) {
                        case 0x01:
                            fingerprint = new byte[size];
                            byteBuffer.get(fingerprint, 0, size);
                            break;
                        case 0x02:
                            signature = new byte[size];
                            byteBuffer.get(signature, 0, size);
                            break;
                        case 0x03:
                            mac = new byte[size];
                            byteBuffer.get(mac, 0, size);
                            break;
                        case 0x04:
                            timestampToken = new byte[size];
                            byteBuffer.get(timestampToken, 0, size);
                            break;
                        default:
                            while(size-- > 0)
                                byteBuffer.get();
                    }
                }
            } while (type > 0);
            this.fingerprint = fingerprint;
            this.signature = signature;
            this.mac = mac;
            this.timestampToken = timestampToken;
            this.footerSize = byteBuffer.getShort();
            this.totalFileSize = byteBuffer.getLong();
            this.totalFileSizeWithoutFooter = dataSize;
        }catch (BufferUnderflowException e) {
            throw new InvalidFileException(e);
        }
    }

    public FooterChunk(byte[] fingerprint, byte[] signature, byte[] mac, byte[] timestampToken, short footerSize, long totalFileSize, long totalFileSizeWithoutFooter, byte[] data) {
        super(CHUNK_TYPE.value(), (short)0, (short)data.length, data);
        this.fingerprint = fingerprint;
        this.signature = signature;
        this.mac = mac;
        this.timestampToken = timestampToken;
        this.footerSize = footerSize;
        this.totalFileSize = totalFileSize;
        this.totalFileSizeWithoutFooter = totalFileSizeWithoutFooter;
    }

    public byte[] fingerprint() {
        return fingerprint;
    }

    public byte[] signature() {
        return signature;
    }

    public byte[] mac() {
        return this.mac;
    }

    public byte[] timestampToken() {
        return this.timestampToken;
    }

    public short footerSize() {
        return footerSize;
    }

    public long totalFileSize() {
        return totalFileSize;
    }

    public static final Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private byte[] fingerprint = null;
        private byte[] signature = null;
        private byte[] mac = null;
        private byte[] timestampToken = null;
        private short footerSize = 0;
        private long totalFileSizeWithoutFooter = 0;

        private Builder() {
        }

        public Builder withFingerprint(byte[] fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        public Builder withSignature(byte[] signature) {
            this.signature = signature;
            return this;
        }

        public Builder withMac(byte[] mac) {
            this.mac = mac;
            return this;
        }

        public Builder withTimestampToken(byte[] timestampToken) {
            this.timestampToken = timestampToken;
            return this;
        }

        public Builder withFooterSize(short footerSize) {
            this.footerSize = footerSize;
            return this;
        }

        public Builder withTotalFileSizeWithoutFooter(long totalFileSizeWithoutFooter) {
            this.totalFileSizeWithoutFooter = totalFileSizeWithoutFooter;
            return this;
        }

        public FooterChunk build() {
            int needSize = 0;
            if(this.fingerprint != null) {
                needSize += 3 + this.fingerprint.length;
            }
            if(this.signature != null) {
                needSize += 3 + this.signature.length;
            }
            if(this.mac != null) {
                needSize += 3 + this.mac.length;
            }
            if(this.timestampToken != null) {
                needSize += 3 + this.timestampToken.length;
            }

            ByteBuffer byteBuffer = ByteBuffer.allocate(11 + needSize).order(ByteOrder.LITTLE_ENDIAN);
            long totalFileSize = this.totalFileSizeWithoutFooter + byteBuffer.capacity() + 3;

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
            if(this.mac != null) {
                byteBuffer.put((byte)0x03);
                byteBuffer.putShort((short)this.mac.length);
                byteBuffer.put(this.mac);
            }
            if(this.timestampToken != null) {
                byteBuffer.put((byte)0x04);
                byteBuffer.putShort((short)this.timestampToken.length);
                byteBuffer.put(this.timestampToken);
            }
            byteBuffer.put((byte)0);
            byteBuffer.putShort(this.footerSize);
            byteBuffer.putLong(totalFileSize);
            byteBuffer.flip();
            return new FooterChunk(fingerprint, signature, mac, timestampToken, footerSize, totalFileSize, totalFileSizeWithoutFooter, byteBuffer.array());
        }
    }
}
