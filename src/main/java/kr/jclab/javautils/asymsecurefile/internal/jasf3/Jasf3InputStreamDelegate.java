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
import kr.jclab.javautils.asymsecurefile.internal.InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.SignatureHeader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

public class Jasf3InputStreamDelegate extends InputStreamDelegate {
    private enum State {
        READ_HEADER(0),
        READ_DATA(1),
        READ_FOOTER(2),
        READ_DONE(3);

        private final int value;
        State(int value) {
            this.value = value;
        }
        public int value() {
            return value;
        }
    }

    private final BouncyCastleProvider workSecurityProvider = new BouncyCastleProvider();

    /**
     * < 0x80 : Jasf Header
     * 0x80 0000 ~ 0x80 FFFF : User Chunk
     */
    private final Map<Integer, Chunk> rawChunkMap = new HashMap<>();

    private Map<Short, UserChunk> cachedUserChunkMap = null;

    private transient byte[] authKey = null;

    private transient byte[] authEncKey = null;

    private AlgorithmInfo algorithmInfo = null;

    private transient Key asymKey = null;
    private transient KeyPair asymKeyPair = null;
    private transient PublicKey localPublicKey = null;

    private ReadingChunk readingChunk = new ReadingChunk();

    private State state = State.READ_HEADER;
    private Deque<DataChunkQueueItem> cipherDataQueue = new ConcurrentLinkedDeque<>();
    private Deque<DataChunkQueueItem> plainDataQueue = new ConcurrentLinkedDeque<>();

    private DefaultHeaderChunk defaultHeaderChunk;
    private byte[] macKey;

    private boolean footerValidated = false;
    private transient MessageDigest fingerprintDigest = null;
    private transient Cipher dataCipher = null;

    private boolean basicInited = false;
    private boolean readPrepared = false;

    public Jasf3InputStreamDelegate(InputStream inputStream, Provider securityProvider, SignatureHeader signatureHeader) {
        super(inputStream, securityProvider, signatureHeader);
    }

    @Override
    public void setAuthKey(byte[] authKey) throws IOException {
        this.authKey = authKey;
        if(!this.basicInited && this.authKey != null && (this.state != State.READ_HEADER))
            initBasic();
    }

    @Override
    public void setAsymKey(Key key) {
        this.asymKey = key;
    }

    @Override
    public void setAsymKey(KeyPair keyPair) {
        this.asymKeyPair = keyPair;
    }

    private int readPayload(State runState, boolean blocking) throws IOException {
        int rc = 1;

        if(runState == State.READ_DATA) {
            DataChunkQueueItem item;
            if(!this.readPrepared)
                prepareReadData();
            while ((item = this.cipherDataQueue.poll()) != null) {
                this.plainDataQueue.add(new DataChunkQueueItem(this.dataCipher.update(item.getBuffer(), 0, item.getSize())));
            }
        }

        while (((this.inputStream.available() > 0) || blocking) && (rc == 1)) {
            if (this.readingChunk.read(this.inputStream, blocking, this.fingerprintDigest)) {
                switch(this.state) {
                    case READ_HEADER:
                        if (this.readingChunk.primaryType != Jasf3ChunkType.DATA_STREAM.value()) {
                            int code = this.readingChunk.primaryType & 0xFF;
                            if((code & 0x80) != 0) {
                                code = 0x800000 | this.readingChunk.userCode;
                            }
                            rawChunkMap.put(code, Jasf3ChunkResolver.parseChunk(this.readingChunk.primaryType, (short) 0, this.readingChunk.size, this.readingChunk.getData()));
                            break;
                        }
                        this.state = State.READ_DATA;
                        if(!this.basicInited && this.authKey != null)
                            initBasic();
                        rc = 0;
                        if(!this.readPrepared && ((this.asymKey != null) || (this.asymKeyPair != null)) && (this.authKey != null))
                            prepareReadData();
                        if(!this.readPrepared) {
                            this.cipherDataQueue.offer(new DataChunkQueueItem(this.readingChunk.getData(), this.readingChunk.size));
                            break;
                        }
                        // Continue process to READ_DATA
                    case READ_DATA:
                        if (this.readingChunk.primaryType == Jasf3ChunkType.DATA_STREAM.value()) {
                            this.plainDataQueue.offer(new DataChunkQueueItem(this.dataCipher.update(this.readingChunk.getData(), 0, this.readingChunk.size)));
                            break;
                        }
                    case READ_FOOTER:
                        rawChunkMap.put(this.readingChunk.primaryType & 0xff, Jasf3ChunkResolver.parseChunk(this.readingChunk.primaryType, (short) 0, this.readingChunk.size, this.readingChunk.getData()));
                        this.state = State.READ_DONE;
                        validateFooter();
                        break;
                }
                this.readingChunk.reset();
                if(this.state == State.READ_DATA)
                    break;
            }
        }

        return rc;
    }

    @Override
    public int headerRead() throws IOException {
        if(this.fingerprintDigest == null) {
            try {
                this.fingerprintDigest = MessageDigest.getInstance("SHA-256", this.workSecurityProvider);
            } catch (NoSuchAlgorithmException e) {
                throw new IOException(e);
            }
        }
        return this.readPayload(State.READ_HEADER, false);
    }

    @Override
    public boolean isDataReadable() {
        return this.state.value() >= State.READ_DATA.value();
    }

    @Override
    public int available() {
        DataChunkQueueItem dataChunkQueueItem = this.plainDataQueue.poll();
        if(dataChunkQueueItem == null)
            return 0;
        return dataChunkQueueItem.readRemaining();
    }

    @Override
    public int read(byte[] buffer, int offset, int size) throws IOException {
        int readSize = 0;
        int readResult;
        if(this.state != State.READ_DATA) {
            readResult = this.readPayload(State.READ_HEADER, false);
        }else {
            readResult = this.readPayload(State.READ_DATA, false);
            if (readResult == 0) {
                // If data read has done
                this.readPayload(State.READ_FOOTER, true);
            }
        }
        synchronized (this.plainDataQueue) {
            DataChunkQueueItem dataChunkQueueItem = this.plainDataQueue.poll();
            if(dataChunkQueueItem != null) {
                readSize = Math.min(size, dataChunkQueueItem.readRemaining());
                System.arraycopy(dataChunkQueueItem.getBuffer(), dataChunkQueueItem.readPosition(), buffer, offset, readSize);
                dataChunkQueueItem.incReadPosition(readSize);
                if(dataChunkQueueItem.readRemaining() > 0) {
                    this.plainDataQueue.offerFirst(dataChunkQueueItem); // Re-insert
                }
            }else{
                if(this.state == State.READ_DONE)
                    return -1;
            }
        }
        return readSize;
    }

    private void parseUserChunks() throws IOException {
        if(this.cachedUserChunkMap != null)
            return ;

        final Map<Short, UserChunk> userChunkMap = new HashMap<>();

        for(Map.Entry<Integer, Chunk> entry : rawChunkMap.entrySet()) {
            if((entry.getKey() & 0x800000) != 0) {
                RawUserChunk rawUserChunk = (RawUserChunk)entry.getValue();
                if(rawUserChunk.getFlag() == Chunk.Flag.EncryptedWithAuthEncKey) {
                    byte[] dataIV = Arrays.copyOf(rawUserChunk.getData(), 16);
                    Cipher cipher = null;
                    byte[] plaintext;
                    try {
                        cipher = createChunkCipher(dataIV, this.authEncKey, this.authKey);
                        plaintext = cipher.doFinal(rawUserChunk.getData(), 16, rawUserChunk.getDataSize() - 16);
                    } catch (AEADBadTagException e) {
                        throw new ValidateFailedException("UserChunk integrity validation failed");
                    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                        throw new IOException(e);
                    }
                    userChunkMap.put((short) (entry.getKey() & 0xFFFF), new RawUserChunk(rawUserChunk.getPrimaryType(), rawUserChunk.getUserCode(), (short)plaintext.length, plaintext));
                }else{
                    userChunkMap.put((short) (entry.getKey() & 0xFFFF), new RawUserChunk(rawUserChunk));
                }
            }
        }

        this.cachedUserChunkMap = userChunkMap;
    }

    @Override
    public Enumeration<UserChunk> userChunks() throws IOException {
        parseUserChunks();
        List<UserChunk> items = new ArrayList<>(rawChunkMap.size());
        for(Map.Entry<Short, UserChunk> entry : cachedUserChunkMap.entrySet()) {
            items.add(entry.getValue());
        }
        return Collections.enumeration(items);
    }

    @Override
    public UserChunk getUserChunk(short code) throws IOException {
        parseUserChunks();
        return cachedUserChunkMap.get(code);
    }

    private Chunk getChunk(Jasf3ChunkType type) {
        return rawChunkMap.get((int)type.value());
    }

    @Override
    public void validate() throws IOException {
        validateFooter();
    }

    private <T extends Chunk> T getSpecialChunk(Class<T> clazz, boolean required) throws IOException {
        Jasf3ChunkType chunkType;
        try {
            Field chunkTypeField = clazz.getField("CHUNK_TYPE");
            chunkType = (Jasf3ChunkType)chunkTypeField.get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        Chunk chunk = getChunk(chunkType);
        if(chunk == null && required)
            throw new IOException("Chunk '" + clazz.getSimpleName() + "' empty");
        return (T)chunk;
    }

    private void initBasic() throws IOException {
        this.defaultHeaderChunk = getSpecialChunk(DefaultHeaderChunk.class, true);
        try {
            Mac authEncKeyMac = Mac.getInstance("HmacSHA256");
            authEncKeyMac.init(new SecretKeySpec(this.authKey, authEncKeyMac.getAlgorithm()));
            this.authEncKey = authEncKeyMac.doFinal(defaultHeaderChunk.seed());
        }catch(Exception e) {
            throw new IOException(e);
        }
    }

    private void prepareReadData() throws IOException {
        byte[] dataKey;

        if(this.authKey == null) {
            throw new IOException("Empty authKey");
        }

        AsymAlgorithmChunk asymAlgorithmChunk = getSpecialChunk(AsymAlgorithmChunk.class, true);
        DataAlgorithmChunk dataAlgorithmChunk = getSpecialChunk(DataAlgorithmChunk.class, true);
        DataIvChunk dataIVChunk = getSpecialChunk(DataIvChunk.class, true);

        this.algorithmInfo = asymAlgorithmChunk.algorithmInfo();

        if(this.asymKey == null) {
            if(this.asymKeyPair == null)
                throw new IllegalStateException("Empty asymKey");

            switch (this.defaultHeaderChunk.operationType()) {
                case SIGN:
                    this.asymKey = this.asymKeyPair.getPublic();
                    break;
                case PUBLIC_ENCRYPT:
                    this.asymKey = this.asymKeyPair.getPrivate();
                    break;
            }
        }

        if(this.asymKey == null) {
            throw new IOException("Empty asymKey");
        }

        // ========== Get SeedKey and DataKey & Store to chunk ==========

        try {
            if(this.defaultHeaderChunk.operationType() == OperationType.PUBLIC_ENCRYPT) {
                EncryptedSeedKeyChunk encryptedSeedKeyChunk = getSpecialChunk(EncryptedSeedKeyChunk.class, true);
                SeedKeyCheckChunk seedKeyCheckChunk = getSpecialChunk(SeedKeyCheckChunk.class, true);

                byte[] seedKey;
                Mac dataKeyMac = Mac.getInstance("HmacSHA512", this.workSecurityProvider);
                dataKeyMac.init(new SecretKeySpec(this.authKey, dataKeyMac.getAlgorithm()));

                if ((this.algorithmInfo.getAlgorithm() == AsymAlgorithm.EC) || (this.algorithmInfo.getAlgorithm() == AsymAlgorithm.PRIME)) {
                    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", this.securityProvider);
                    KeyFactory keyFactory = KeyFactory.getInstance(this.algorithmInfo.getAlgorithm().getAlgorithm(), this.workSecurityProvider);
                    X509EncodedKeySpec localKeySpec = new X509EncodedKeySpec(encryptedSeedKeyChunk.data());
                    this.localPublicKey = keyFactory.generatePublic(localKeySpec);
                    keyAgreement.init(this.asymKey);
                    keyAgreement.doPhase(this.localPublicKey, true);
                    seedKey = keyAgreement.generateSecret();
                } else if (this.algorithmInfo.getAlgorithm() == AsymAlgorithm.RSA) {
                    Cipher seedKeyCipher = Cipher.getInstance("RSA/ECB/OAEPPadding", this.securityProvider);
                    seedKeyCipher.init(Cipher.DECRYPT_MODE, this.asymKey);
                    seedKey = seedKeyCipher.doFinal(encryptedSeedKeyChunk.data());
                } else {
                    throw new RuntimeException("Unknown AsymKey Type");
                }
                byte[] bigKey = dataKeyMac.doFinal(seedKey);
                dataKey = Arrays.copyOfRange(bigKey, 0, 32);
                this.macKey = Arrays.copyOfRange(bigKey, 32, 64);

                if(!seedKeyCheckChunk.verify(seedKey)) {
                    throw new ValidateFailedException("Different Key");
                }

                int dataKeySize = dataAlgorithmChunk.dataAlgorithm().getKeySize();
                if (dataKeySize != dataKey.length) {
                    if (dataKeySize > dataKey.length) {
                        dataKey = Arrays.copyOf(dataKey, dataKeySize);
                    } else {
                        throw new RuntimeException("Not support key size = " + (dataKeySize * 8));
                    }
                }
            }else{
                dataKey = this.authEncKey;
                this.macKey = this.authKey;
            }

            this.dataCipher = createDataCipher(dataAlgorithmChunk, dataIVChunk.getIv(), dataKey, this.macKey);
        } catch (Exception e) {
            throw new IOException(e);
        }

        this.readPrepared = true;
    }

    private void validateFooter() throws IOException {
        if(this.footerValidated)
            return ;

        try {
            byte[] lastData = this.dataCipher.doFinal();
            if (lastData != null && lastData.length > 0) {
                this.plainDataQueue.add(new DataChunkQueueItem(lastData));
            }
        } catch (AEADBadTagException badTagException) {
            throw new ValidateFailedException("Data integrity validation failed");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException(e);
        }

        byte[] fingerprint = this.fingerprintDigest.digest();
        FooterChunk footerChunk = getSpecialChunk(FooterChunk.class, true);
        if(!Arrays.equals(fingerprint, footerChunk.fingerprint())) {
            throw new ValidateFailedException("Header Integrity validation failed");
        }
        try {
            if(this.defaultHeaderChunk.operationType() == OperationType.SIGN) {
                verifySignData(footerChunk.signature(), fingerprint);
            }else{
                Mac mac = Mac.getInstance("HmacSHA256", this.workSecurityProvider);
                mac.init(new SecretKeySpec(this.macKey, mac.getAlgorithm()));
                mac.update(fingerprint);
                if(!Arrays.equals(footerChunk.mac(), mac.doFinal())) {
                    throw new ValidateFailedException();
                }
            }
        } catch (ValidateFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }

        footerValidated = true;
    }

    private void verifySignData(byte[] sig, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, ValidateFailedException, SignatureException {
        // Sign
        Signature signature = Signature.getInstance(this.algorithmInfo.getAlgorithm().getSignatureAlgorithm(), this.securityProvider);
        signature.initVerify((PublicKey) this.asymKey);
        signature.update(data);
        if (!signature.verify(sig))
            throw new ValidateFailedException("Integrity validation failed");
    }

    private Cipher createDataCipher(DataAlgorithmChunk dataAlgorithmChunk, byte[] dataIV, byte[] key, byte[] authKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(dataAlgorithmChunk.dataAlgorithm().getIdentifier().getId(), this.workSecurityProvider);
        }catch (NoSuchAlgorithmException algoException) {
            cipher = Cipher.getInstance(dataAlgorithmChunk.dataAlgorithm().getAlgorithm(), this.workSecurityProvider);
        }

        if(dataAlgorithmChunk.dataAlgorithm().isContainMac()) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, dataIV);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, dataAlgorithmChunk.dataAlgorithm().getAlgorithm().split("/", 2)[0]), gcmParameterSpec);
            cipher.updateAAD(authKey);
        }else{
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, dataAlgorithmChunk.dataAlgorithm().getAlgorithm().split("/", 2)[0]), new IvParameterSpec(dataIV));
        }
        return cipher;
    }

    private Cipher createChunkCipher(byte[] dataIV, byte[] key, byte[] authKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", this.workSecurityProvider);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, dataIV);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), gcmParameterSpec);
        cipher.updateAAD(authKey);
        return cipher;
    }

    private final class ReadingChunk {
        public byte primaryType = 0;
        public short userCode = 0;
        public short size = 0;
        private int step = 0;

        private final byte[] tempBuffer = new byte[4096];
        private ByteArrayOutputStream dataArrayStream = null;

        public ReadingChunk() {
            reset();
        }

        public void reset() {
            this.step = 0;
            this.primaryType = 0;
            this.dataArrayStream = new ByteArrayOutputStream(4096);
        }

        /**
         * @return true if complete, otherwise false.
         */
        public boolean read(InputStream inputStream, boolean blocking, MessageDigest messageDigest) throws IOException {
            while((inputStream.available() > 0) || blocking) {
                int temp;
                switch (this.step) {
                    case 0:
                        temp = inputStream.read();
                        if(temp < 0)
                            throw new EOFException();
                        this.primaryType = (byte)temp;
                        if(this.primaryType != Jasf3ChunkType.FOOTER_FINGERPRINT.value())
                            messageDigest.update((byte)temp);
                        this.userCode = 0;
                        this.size = 0;
                        this.dataArrayStream.reset();
                        if((temp & 0x80) == 0)
                            this.step = 3;
                        else
                            this.step++;
                        break;
                    case 1:
                    case 2:
                        temp = inputStream.read();
                        if(temp < 0)
                            throw new EOFException();
                        if(this.primaryType != Jasf3ChunkType.FOOTER_FINGERPRINT.value())
                            messageDigest.update((byte)temp);
                        this.userCode |= (temp & 0xFF) << ((this.step - 1) * 8);
                        this.step++;
                        break;
                    case 3:
                    case 4:
                        temp = inputStream.read();
                        if(temp < 0)
                            throw new EOFException();
                        if(this.primaryType != Jasf3ChunkType.FOOTER_FINGERPRINT.value())
                            messageDigest.update((byte)temp);
                        this.size |= (temp & 0xFF) << ((this.step - 3) * 8);
                        this.step++;
                        break;
                    case 5:
                        if(this.size <= 0) {
                            throw new InvalidFileException("wrong chunk size (" + this.size + ")");
                        }
                        if(this.dataArrayStream.size() < this.size) {
                            int remaining = this.size - this.dataArrayStream.size();
                            int avail = inputStream.available();
                            avail = Math.min(remaining, avail);
                            avail = Math.min(avail, tempBuffer.length);
                            inputStream.read(this.tempBuffer, 0, avail);
                            if(this.primaryType != Jasf3ChunkType.FOOTER_FINGERPRINT.value())
                                messageDigest.update(this.tempBuffer, 0, avail);
                            this.dataArrayStream.write(this.tempBuffer, 0, avail);
                        }
                        if(this.dataArrayStream.size() == this.size) {
                            return true;
                        }else if (this.dataArrayStream.size() > this.size) {
                            throw new RuntimeException("System fault");
                        }
                        break;
                }
            }
            return false;
        }

        public byte[] getData() {
            return this.dataArrayStream.toByteArray();
        }
    }

    private final class DataChunkQueueItem {
        private final byte[] buffer;
        private int readPosition = 0;
        private int size = 0;

        public DataChunkQueueItem(byte[] buffer, int size) {
            this.size = size;
            this.buffer = buffer;
        }

        public DataChunkQueueItem(byte[] buffer) {
            this.size = buffer.length;
            this.buffer = buffer;
        }

        public byte[] getBuffer() {
            return this.buffer;
        }

        public int readPosition() {
            return this.readPosition;
        }

        public int readRemaining() {
            return this.size - this.readPosition;
        }

        public void incReadPosition(int size) {
            this.readPosition += size;
        }

        public int getSize() {
            return this.size;
        }
    }
}
