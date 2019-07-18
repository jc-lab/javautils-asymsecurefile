/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf3;

import kr.jclab.javautils.asymsecurefile.*;
import kr.jclab.javautils.asymsecurefile.internal.AlgorithmInfo;
import kr.jclab.javautils.asymsecurefile.internal.OutputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.SignatureHeader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.interfaces.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Jasf3OutputStreamDelegate extends OutputStreamDelegate {
    private enum State {
        INIT(0),
        WRITE_HEADER(1),
        WRITE_DATA(2),
        WRITE_FOOTER(3);

        private final int value;
        State(int value) {
            this.value = value;
        }
        public int value() {
            return value;
        }
    }

    private final Random random = new SecureRandom();

    private AlgorithmInfo algorithmInfo = null;
    private transient Key asymKey = null;
    private DataAlgorithm dataAlgorithm = null;
    private int dataChunkSize = 4096;

    private KeyPair localKeyPair = null;

    private State state = State.INIT;

    /**
     * < 0x80 : Jasf Header
     * 0x80 0000 ~ 0x80 FFFF : User Chunk
     */
    private final Map<Integer, Chunk> rawChunkMap = new HashMap<>();

    private byte[] authKey = null;
    private byte[] authTag = null;

    private transient byte[] dataKey = null;
    private transient Cipher dataCipher = null;
    private transient Mac dataMac = null;
    private transient MessageDigest fingerprintDigest = null;

    private ByteArrayOutputStream writingDataTempBuffer = null;

    public Jasf3OutputStreamDelegate(OperationType operationType, OutputStream outputStream, Provider securityProvider) {
        super(operationType, outputStream, securityProvider);
    }

    @Override
    public void init(Key key, DataAlgorithm dataAlgorithm, byte[] authKey) throws IOException {
        if(state != State.INIT)
            return ;

        this.algorithmInfo = new AlgorithmInfo(key);
        if(this.algorithmInfo.getAlgorithm() == null) {
            throw new NotSupportAlgorithmException();
        }
        this.asymKey = key;
        this.authKey = authKey;
        this.dataAlgorithm = dataAlgorithm;
        setRawChunk(AsymAlgorithmChunk.builder().withAlgorithmInfo(this.algorithmInfo).build());

        // ========== Generate SeedKey and DataKey & Store to chunk ==========

        try {
            EncryptedSeedKeyChunk.Builder encryptedSeedKeyChunkBuilder = EncryptedSeedKeyChunk.builder();
            Mac dataKeyMac = Mac.getInstance("HmacSHA256");
            byte[] seedKey;
            dataKeyMac.init(new SecretKeySpec(this.authKey, dataKeyMac.getAlgorithm()));

            if (this.asymKey instanceof ECKey) {
                byte[] encodedLocalKey;
                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", this.securityProvider);
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.algorithmInfo.getAlgorithm().getAlgorithm());
                keyPairGenerator.initialize(((ECKey) this.asymKey).getParams().getCurve().getField().getFieldSize());
                localKeyPair = keyPairGenerator.generateKeyPair();
                if (this.asymKey instanceof ECPrivateKey) {
                    // For Sign
                    keyAgreement.init(this.asymKey);
                    keyAgreement.doPhase(localKeyPair.getPublic(), true);
                    encodedLocalKey = localKeyPair.getPrivate().getEncoded();
                } else if (this.asymKey instanceof ECPublicKey) {
                    // Public Encrypt
                    keyAgreement.init(localKeyPair.getPrivate());
                    keyAgreement.doPhase(this.asymKey, true);
                    encodedLocalKey = localKeyPair.getPublic().getEncoded();
                } else {
                    throw new RuntimeException("Unknown Error");
                }
                seedKey = keyAgreement.generateSecret();
                encryptedSeedKeyChunkBuilder.withData(encodedLocalKey);
            } else if (this.asymKey instanceof RSAKey) {
                Cipher seedKeyCipher = Cipher.getInstance("RSA/ECB/OAEPPadding", this.securityProvider);
                seedKey = new byte[32];
                this.random.nextBytes(seedKey);
                seedKeyCipher.init(Cipher.ENCRYPT_MODE, this.asymKey);
                encryptedSeedKeyChunkBuilder.withData(seedKeyCipher.doFinal(seedKey));
            } else {
                throw new RuntimeException("Unknown AsymKey Type");
            }

            this.dataKey = dataKeyMac.doFinal(seedKey);

            if (this.dataAlgorithm.getKeySize() != this.dataKey.length) {
                if (this.dataAlgorithm.getKeySize() > this.dataKey.length) {
                    this.dataKey = Arrays.copyOf(this.dataKey, this.dataAlgorithm.getKeySize());
                } else {
                    throw new RuntimeException("Unknown Error");
                }
            }

            setRawChunk(encryptedSeedKeyChunkBuilder.build());
        } catch (Exception e) {
            throw new IOException(e);
        }

        // ========== prepare WriteData =========
        this.setRawChunk(DefaultHeaderChunk.builder().withOperationType(this.operationType).build());
        try {
            byte[] dataIV = new byte[16];
            this.random.nextBytes(dataIV);

            this.fingerprintDigest = MessageDigest.getInstance("SHA-256", this.securityProvider);
            try {
                this.dataCipher = Cipher.getInstance(this.dataAlgorithm.getIdentifier().getId(), this.securityProvider);
            }catch (NoSuchAlgorithmException algoException) {
                this.dataCipher = Cipher.getInstance(this.dataAlgorithm.getAlgorithm(), this.securityProvider);
            }

            if(this.dataAlgorithm.isContainMac()) {
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, dataIV);
                this.dataCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.dataKey, this.dataAlgorithm.getAlgorithm().split("/", 2)[0]), gcmParameterSpec);
                this.dataCipher.updateAAD(this.authKey);
            }else{
                this.dataCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.dataKey, this.dataAlgorithm.getAlgorithm().split("/", 2)[0]), new IvParameterSpec(dataIV));
                this.dataMac = Mac.getInstance("HmacSHA256", this.securityProvider);
            }

            dataIV = this.dataCipher.getIV();

            setRawChunk(DataAlgorithmChunk.builder().withDataAlgorithm(this.dataAlgorithm).build());
            setRawChunk(DataIvChunk.builder().withIv(dataIV).build());
        } catch (Exception e) {
            throw new IOException(e);
        }

        this.state = State.WRITE_HEADER;
    }

    @Override
    public void setUserChunk(short code, UserChunk chunk) {
        if(this.state == State.WRITE_HEADER) {
            throw new IllegalStateException();
        }
        this.rawChunkMap.put(0x800000 | (code & 0xFFFF), chunk);
    }

    @Override
    public void write(byte[] buffer, int off, int size) throws IOException {
        if(this.state == State.WRITE_HEADER) {
            writeHeader();
        }
        int bufferPosition = 0;
        int bufferRemaining = size;
        while(bufferRemaining > 0) {
            if (this.writingDataTempBuffer == null) {
                this.writingDataTempBuffer = new ByteArrayOutputStream(this.dataChunkSize);
            }
            int avail = Math.min(this.dataChunkSize - this.writingDataTempBuffer.size(), bufferRemaining);
            if(avail > 0) {
                this.writingDataTempBuffer.write(buffer, bufferPosition, avail);
            }
            if(this.writingDataTempBuffer.size() >= this.dataChunkSize) {
                writeDataChunk();
                this.writingDataTempBuffer.reset();
            }
            bufferPosition += avail;
            bufferRemaining -= avail;
        }
    }

    @Override
    public void finish() throws IOException {
        if(this.state != State.WRITE_FOOTER) {
            try {
                byte[] ciphertext;
                int pos;
                if(writingDataTempBuffer.size() > 0) {
                    ciphertext = dataCipher.doFinal(this.writingDataTempBuffer.toByteArray(), 0, this.writingDataTempBuffer.size());
                }else{
                    ciphertext = dataCipher.doFinal();
                }
                writeRawChunk(new RawChunk(Jasf3ChunkType.DATA_STREAM.value(), (short)0, (short)ciphertext.length, ciphertext));
                pos = ciphertext.length - this.dataCipher.getBlockSize();
                this.authTag = new byte[this.dataCipher.getBlockSize()];
                System.arraycopy(ciphertext, pos, this.authTag, 0, this.dataCipher.getBlockSize());
            } catch (IllegalBlockSizeException e) {
                throw new IOException(e);
            } catch (BadPaddingException e) {
                throw new IOException(e);
            }
            writeFooter();
            this.state = State.WRITE_FOOTER;
        }
        outputStream.flush();
    }

    private void writeDataChunk() throws IOException {
        byte[] ciphertext = dataCipher.update(this.writingDataTempBuffer.toByteArray(), 0, this.writingDataTempBuffer.size());
        writeRawChunk(new RawChunk(Jasf3ChunkType.DATA_STREAM.value(), (short)0, (short)ciphertext.length, ciphertext));
    }

    private void writeRawChunk(Chunk chunk) throws IOException {
        short userCode = chunk.getUserCode();
        short dataSize = chunk.getDataSize();
        byte[] headBuffer = new byte[5];
        int headSize = 0;
        headBuffer[headSize++] = chunk.getPrimaryType();
        if((chunk.getPrimaryType() & 0x80) != 0) {
            headBuffer[headSize++] = (byte)(userCode & 0xFF);
            headBuffer[headSize++] = (byte)((userCode >>> 8) & 0xFF);
        }
        headBuffer[headSize++] = (byte)(dataSize & 0xFF);
        headBuffer[headSize++] = (byte)((dataSize >>> 8) & 0xFF);
        this.outputStream.write(headBuffer, 0, headSize);
        this.outputStream.write(chunk.getData(), 0, dataSize);
        this.fingerprintDigest.update(headBuffer, 0, headSize);
        this.fingerprintDigest.update(chunk.getData(), 0, dataSize);
    }

    private void setRawChunk(Chunk chunk) {
        this.rawChunkMap.put(chunk.getChunkId(), chunk);
    }

    private void writeHeader() throws IOException {
        outputStream.write(SignatureHeader.SIGNATURE);
        outputStream.write(3); // Version.3
        for(Map.Entry<Integer, Chunk> entry : this.rawChunkMap.entrySet()) {
            writeRawChunk(entry.getValue());
        }
        this.state = State.WRITE_DATA;
    }

    private void writeFooter() throws IOException {
        byte[] fingerprint = this.fingerprintDigest.digest(this.authTag);
        FooterChunk.Builder footerChunkBuilder = FooterChunk.builder()
                .withFingerprint(fingerprint)
                .withTotalFileSizeWithoutFooter(this.getWrittenBytes());

        try {
            footerChunkBuilder.withSignature(signData(fingerprint));
        } catch (Exception e) {
            throw new IOException(e);
        }
        writeRawChunk(footerChunkBuilder.build());
        outputStream.flush();
    }

    private byte[] signData(byte[] data) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        if(this.asymKey instanceof PrivateKey) {
            // Sign
            Signature signature = Signature.getInstance(this.algorithmInfo.getAlgorithm().getSignatureAlgorithm(), this.securityProvider);
            signature.initSign((PrivateKey) this.asymKey);
            signature.update(data);
            return signature.sign();
        }else if(this.localKeyPair != null) {
            // Public Encrypt (EC)
            Signature signature = Signature.getInstance(this.algorithmInfo.getAlgorithm().getSignatureAlgorithm(), this.securityProvider);
            signature.initSign(this.localKeyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        }else if(this.asymKey instanceof RSAPublicKey) {
            // Public Encrypt (RSA)
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding", this.securityProvider);
            cipher.init(Cipher.ENCRYPT_MODE, this.asymKey);
            return cipher.doFinal(data);
        }
        throw new RuntimeException("Unknown Error");
    }
}
