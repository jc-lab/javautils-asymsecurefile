/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4;

import kr.jclab.javautils.asn1streamreader.Asn1ReadResult;
import kr.jclab.javautils.asn1streamreader.Asn1ReaderOptions;
import kr.jclab.javautils.asn1streamreader.Asn1StreamReader;
import kr.jclab.javautils.asymsecurefile.*;
import kr.jclab.javautils.asymsecurefile.internal.*;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.asn.*;
import kr.jclab.javautils.asymsecurefile.internal.utils.CipherAlgorithms;
import kr.jclab.javautils.asymsecurefile.internal.utils.HashAlgorithms;
import kr.jclab.javautils.asymsecurefile.internal.utils.HkdfUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import javax.crypto.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

public class Jasf4InputStreamDelegate extends InputStreamDelegate {
    private enum ReadState {
        BEGIN_SEQUENCE,
        READ_MINOR_VERSION,
        READ_OPERATION_TYPE,
        READING_HEADER,
        DATA_PENDING,
        DATA_READABLE,
        READ_FOOTER,
        END_SEQUENCE
    }

    private final BouncyCastleProvider workSecurityProvider = BCProviderSingletone.getProvider();

    private final Asn1StreamReader asn1StreamReader;

    private ReadState readState = ReadState.BEGIN_SEQUENCE;
    private int minorVersion = 0;
    private OperationType operationType = null;

    private final List<byte[]> fingerprintPending = new LinkedList<>();
    private final List<Asn1ObjectChunkBase> pendingChunks = new LinkedList<>();
    private final List<Asn1DataChunk> pendingDataChunks = new LinkedList<>();

    private HashAlgorithms.AlgorithmEntry fingerprintAlgorithm = null;
    private Digest fingerprintDigest = null;
    private byte[] computedFingerprint = null;

    private transient KeyPair keyPair = null;
    private transient AsymmetricKeyObject asymKey = null;

    private boolean authKeyValidated = false;
    private boolean asymKeyValidated = false;

    private final Map<Integer, Asn1ObjectChunkBase> chunkMap = new HashMap<>();

    private Jasf4AuthKeyUtils.DerivedKeys authKeyDerivedKeys = null;
    private byte[] authKeyCryptoIv = null;

    private CipherAlgorithms.AlgorithmEntry dataAlgorithm = null;
    private Cipher dataCipher = null;
    private Mac dataMac = null;

    private IOException validateException = null;

    private final Deque<DataChunkQueueItem> plainDataQueue = new ConcurrentLinkedDeque<>();

    private Map<Integer, UserChunk> cachedUserChunks = null;

    public Jasf4InputStreamDelegate(InputStreamOptions options) throws IOException {
        super(options);
        this.asn1StreamReader = new Asn1StreamReader(
                options.getInputStream(),
                Asn1ReaderOptions.builder()
                        .stripSequence(true)
                        .build()
        );
    }

    private void updateFingerprintPayload(byte[] data) {
        if (this.fingerprintDigest == null) {
            if (computedFingerprint == null) {
                this.fingerprintPending.add(data);
            }
        }else{
           this.fingerprintDigest.update(data, 0, data.length);
        }
    }

    private boolean isKeysPresent() {
        return (this.options.getAuthKey() != null) && ((this.asymKey != null) || (this.keyPair != null));
    }

    @Override
    public void setAuthKey(byte[] authKey) throws IOException {
        this.options.setAuthKey(authKey);
        initBasic();
    }

    @Override
    public void setAsymKey(Key key) {
        try {
            this.asymKey = AsymmetricKeyObject.fromKey(key, this.options.getSecurityProvider());
        } catch (NotSupportAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setAsymKey(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    private void processChunk(Asn1ReadResult readResult) throws IOException {
        Asn1ObjectChunkBase chunk = ChunkResolver.parseChunk(readResult.getObject());
        if(chunk == null) {
            this.updateFingerprintPayload(readResult.getRawBuffer());
            return ;
        }

        if((!(chunk instanceof Asn1AbstractEncryptedChunk)) && !ChunkId.Data.equals(chunk.getChunkId())) {
            this.chunkMap.computeIfAbsent(chunk.getRawId(), (k) -> chunk);
        }

        if(!ChunkId.Fingerprint.equals(chunk.getChunkId())) {
            this.updateFingerprintPayload(readResult.getRawBuffer());
        }

        if((ReadState.DATA_PENDING.equals(this.readState) || (ReadState.DATA_READABLE.equals(this.readState))) && (!ChunkId.Data.equals(chunk.getChunkId()))) {
            this.processDataChunk(null);
            this.readState = ReadState.READ_FOOTER;
        }

        if (ChunkId.DefaultHeader.equals(chunk.getChunkId())) {
            Asn1DefaultHeaderChunk defaultHeaderChunk = (Asn1DefaultHeaderChunk) chunk;
            this.fingerprintAlgorithm = HashAlgorithms.findByOid(defaultHeaderChunk.getFingerprintAlgorithm());
            this.fingerprintDigest = fingerprintAlgorithm.createDigest();
            byte[] buf;
            while((!this.fingerprintPending.isEmpty()) && ((buf = this.fingerprintPending.remove(0)) != null)) {
                this.fingerprintDigest.update(buf, 0, buf.length);
            }
        } else if (ChunkId.Fingerprint.equals(chunk.getChunkId())) {
            byte[] computedFingerprint = new byte[this.fingerprintDigest.getDigestSize()];
            this.fingerprintDigest.doFinal(computedFingerprint, 0);
            this.computedFingerprint = computedFingerprint;
        } else if (ChunkId.Data.equals(chunk.getChunkId())) {
            if(this.readState.ordinal() <= ReadState.DATA_PENDING.ordinal()) {
                this.pendingChunks.add(chunk);
            }else{
                this.processDataChunk((Asn1DataChunk)chunk);
            }
            if(this.readState == ReadState.READING_HEADER) {
                this.headerComplete();
            }
        } else if (chunk instanceof Asn1AbstractEncryptedChunk) {
            this.pendingChunks.add(chunk);
        }
    }

    private void processDataChunk(Asn1DataChunk chunk) {
        try {
            byte[] plaintext = null;
            if (chunk != null) {
                byte[] ciphertext = chunk.getBytesData();
                if (this.dataMac != null) {
                    this.dataMac.update(ciphertext, 0, ciphertext.length);
                }
                plaintext = this.dataCipher.update(ciphertext);
            } else {
                if (this.dataAlgorithm.isGcmMode()) {
                    Asn1MacOfEncryptedDataChunk macChunk = this.getChunk(Asn1MacOfEncryptedDataChunk.class, Asn1MacOfEncryptedDataChunk.CHUNK_ID);
                    plaintext = this.dataCipher.doFinal(macChunk.getBytesData());
                } else {
                    plaintext = this.dataCipher.doFinal();
                }
            }
            if (plaintext != null && plaintext.length > 0) {
                this.plainDataQueue.add(new DataChunkQueueItem(plaintext));
            }
        } catch (BadPaddingException | IllegalBlockSizeException badTagException) {
            // AEADBadTagException extends BadPaddingException
            this.validateException = new ValidateFailedException(badTagException);
        }
    }

    private void headerComplete() throws IOException {
        this.readState = ReadState.DATA_PENDING;
        if (this.initBasic()) {
            this.prepareReadData();
        }
    }

    private boolean initBasic() throws IOException {
        if(this.authKeyValidated) {
            return true;
        }
        if(this.options.getAuthKey() == null || !ReadState.DATA_PENDING.equals(this.readState)) {
            return false;
        }

        Asn1AuthKeyCheckChunk authKeyCheckChunk = this.getChunk(Asn1AuthKeyCheckChunk.class, Asn1AuthKeyCheckChunk.CHUNK_ID);
        Asn1DefaultHeaderChunk defaultHeaderChunk = this.getChunk(Asn1DefaultHeaderChunk.class, Asn1DefaultHeaderChunk.CHUNK_ID);

        if (!Jasf4AuthKeyUtils.checkAuthKeyChunk(authKeyCheckChunk, this.options.getAuthKey())) {
            throw new ValidateFailedException("wrong authKey");
        }

        this.authKeyDerivedKeys = Jasf4AuthKeyUtils.deriveKeys(options.getAuthKey());
        this.authKeyCryptoIv = defaultHeaderChunk.getAuthKeyCryptionIv().getOctets();

        try {
            Asn1ObjectChunkBase chunk;
            while ((!this.pendingChunks.isEmpty()) && (chunk = this.pendingChunks.remove(0)) != null) {
                if (chunk instanceof Asn1AbstractEncryptedChunk) {
                    Asn1AbstractEncryptedChunk encryptedChunk = (Asn1AbstractEncryptedChunk) chunk;
                    CipherAlgorithms.CreateCipherResult cipherResult = CipherAlgorithms.findByOid(defaultHeaderChunk.getChunkCryptoAlgorithm()).createCipher(
                            CipherAlgorithms.CryptoParams.builder(CipherAlgorithms.DECRYPT_MODE)
                                    .iv(this.authKeyCryptoIv)
                                    .securityProvider(this.workSecurityProvider)
                                    .build(),
                            this.authKeyDerivedKeys.encryptKey
                    );
                    this.chunkMap.put(encryptedChunk.getRawId(), encryptedChunk.decrypt(cipherResult.getCipher()));
                }else if(chunk instanceof Asn1DataChunk) {
                    this.pendingDataChunks.add((Asn1DataChunk)chunk);
                }
            }
        }catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }

        this.authKeyValidated = true;
        this.prepareReadData();

        return true;
    }

    private void prepareReadData() throws IOException {
        if(!this.isKeysPresent()) {
            return ;
        }
        if(this.asymKeyValidated) {
            return ;
        }

        try {
            Asn1DefaultHeaderChunk defaultHeaderChunk = this.getChunk(Asn1DefaultHeaderChunk.class, Asn1DefaultHeaderChunk.CHUNK_ID);

            Asn1DataKeyInfoChunk dataKeyInfoChunk = null;
            byte[] dataCryptoKey = null;
            byte[] dataMacKey = null;
            if (OperationType.SIGN.equals(this.operationType)) {
                if (this.asymKey == null && this.keyPair != null) {
                    this.asymKey = AsymmetricKeyObject.fromKey(this.keyPair.getPublic(), this.options.getSecurityProvider());
                }
                assert this.asymKey != null;
                if (!defaultHeaderChunk.getAsymmetricAlgorithmType().equals(this.asymKey.getAlgorithmType())) {
                    throw new ValidateFailedException("Wrong asym key");
                }
                dataKeyInfoChunk = this.getChunk(Asn1DataKeyInfoChunk.class, Asn1DataKeyInfoChunk.CHUNK_ID);
            }
            if (OperationType.PUBLIC_ENCRYPT.equals(this.operationType)) {
                if(this.asymKey == null && this.keyPair != null) {
                    this.asymKey = AsymmetricKeyObject.fromKey(this.keyPair, this.options.getSecurityProvider());
                }
                assert this.asymKey != null;
                if (!defaultHeaderChunk.getAsymmetricAlgorithmType().equals(this.asymKey.getAlgorithmType())) {
                    throw new ValidateFailedException("Wrong asym key");
                }
                if (this.asymKey.isPrivateDecryptable()) {
                    Asn1EncryptedDataKeyInfoChunk encryptedDataKeyInfoChunk = this.getChunk(Asn1EncryptedDataKeyInfoChunk.class, Asn1EncryptedDataKeyInfoChunk.CHUNK_ID);
                    try {
                        byte[] plaintext = this.asymKey.privateDecrypt(encryptedDataKeyInfoChunk.getBytesData());
                        dataKeyInfoChunk = Asn1DataKeyInfoChunk.fromDataPart(plaintext);
                    } catch (BadBlockException | IOException | IllegalArgumentException e) {
                        throw new ValidateFailedException("Wrong asym key");
                    }
                    if(!dataKeyInfoChunk.validate()) {
                        throw new ValidateFailedException("Wrong asym key");
                    }
                }else{
                    Asn1EphemeralECPublicKeyChunk ecPublicKeyChunk = this.getChunk(Asn1EphemeralECPublicKeyChunk.class, Asn1EphemeralECPublicKeyChunk.CHUNK_ID);
                    Asn1DHCheckDataChunk dhCheckDataChunk = this.getChunk(Asn1DHCheckDataChunk.class, Asn1DHCheckDataChunk.CHUNK_ID);
                    AsymmetricKeyObject publicKey = AsymmetricKeyObject.fromPublicKey(ecPublicKeyChunk.getData(), this.options.getSecurityProvider());
                    KeyAgreement keyAgreement = this.asymKey.createKeyAgreement();
                    keyAgreement.doPhase(publicKey.getPublicKey(), true);
                    byte[] hkdfResult = HkdfUtils.generateKey(
                            HashAlgorithms.findByOid(NISTObjectIdentifiers.id_sha256),
                            keyAgreement.generateSecret(),
                            96,
                            null
                    );
                    dataCryptoKey = Arrays.copyOfRange(hkdfResult, 0, 32);
                    dataMacKey = Arrays.copyOfRange(hkdfResult, 32, 64);
                    byte[] checkData = Arrays.copyOfRange(hkdfResult, 64, 96);
                    if(!Arrays.equals(dhCheckDataChunk.getBytesData(), checkData)) {
                        throw new ValidateFailedException("Wrong asym key");
                    }
                }
            }
            if(dataKeyInfoChunk != null) {
                dataCryptoKey = dataKeyInfoChunk.getDataKey();
                dataMacKey = dataKeyInfoChunk.getMacKey();
            }
            CipherAlgorithms.AlgorithmEntry dataAlgorithm = CipherAlgorithms.findByOid(defaultHeaderChunk.getDataCryptoAlgorithm());
            CipherAlgorithms.CryptoParams.Builder dataCryptoParamsBuilder = CipherAlgorithms.CryptoParams.builder(CipherAlgorithms.DECRYPT_MODE);
            Asn1DataCryptoAlgorithmParameterSpecChunk dataCryptoAlgorithmParameterSpecChunk = this.getChunk(Asn1DataCryptoAlgorithmParameterSpecChunk.class, Asn1DataCryptoAlgorithmParameterSpecChunk.CHUNK_ID);
            if (dataAlgorithm.isGcmMode()) {
                Asn1GcmParameters gcmParameters = Asn1GcmParameters.getInstance(dataCryptoAlgorithmParameterSpecChunk.getData());
                dataCryptoParamsBuilder
                        .iv(gcmParameters.getNonce())
                        .authTagLength(gcmParameters.getIcvLen());
            }else{
                ASN1OctetString ivOctetString = ASN1OctetString.getInstance(dataCryptoAlgorithmParameterSpecChunk.getData());
                dataCryptoParamsBuilder
                        .iv(ivOctetString.getOctets());

                if (OperationType.PUBLIC_ENCRYPT.equals(this.operationType)) {
                    Asn1DataMacAlgorithmChunk dataMacAlgorithmChunk = this.getChunk(Asn1DataMacAlgorithmChunk.class, Asn1DataMacAlgorithmChunk.CHUNK_ID);
                    HashAlgorithms.AlgorithmEntry macDigestAlgorithm = HashAlgorithms.findByOid(dataMacAlgorithmChunk.getData().getAlgorithm());
                    this.dataMac = new HMac(macDigestAlgorithm.createDigest());
                    this.dataMac.init(new KeyParameter(dataMacKey));
                }
            }
            CipherAlgorithms.CreateCipherResult cipherResult = dataAlgorithm.createCipher(
                    dataCryptoParamsBuilder.build(),
                    dataCryptoKey
            );
            this.dataAlgorithm = dataAlgorithm;
            this.dataCipher = cipherResult.getCipher();
            if(dataAlgorithm.isGcmMode()) {
                this.dataCipher.updateAAD(dataMacKey);
            }
            for(Asn1DataChunk dataChunk : this.pendingDataChunks) {
                this.processDataChunk(dataChunk);
            }
        }catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException e) {
            throw new IOException(e);
        }

        this.readState = ReadState.DATA_READABLE;
    }

    private <T extends Asn1ObjectChunkBase> T getChunk(Class<T> clazz, ChunkId chunkId) {
        return getChunk(clazz, chunkId.getValue());
    }

    private <T extends Asn1ObjectChunkBase> T getChunk(Class<T> clazz, int chunkId) {
        return (T)this.chunkMap.get(chunkId);
    }

    @Override
    public int headerRead() throws IOException {
        while(this.readState.ordinal() <= ReadState.READING_HEADER.ordinal()) {
            Asn1ReadResult readResult = this.asn1StreamReader.readObject(true);
            if (readResult == null) {
                return 1;
            }
            switch (this.readState) {
                case BEGIN_SEQUENCE:
                    if (!Asn1ReadResult.ReadType.BEGIN_SEQUENCE.equals(readResult.getReadType())) {
                        throw new IOException("Wrong payload order");
                    }
                    this.updateFingerprintPayload(readResult.getRawBuffer());
                    this.readState = ReadState.READ_MINOR_VERSION;
                    break;
                case READ_MINOR_VERSION:
                    if (!Asn1ReadResult.ReadType.OBJECT.equals(readResult.getReadType())) {
                        throw new IOException("Wrong payload order");
                    }
                    this.updateFingerprintPayload(readResult.getRawBuffer());
                    this.minorVersion = ASN1Integer.getInstance(readResult.getObject()).intValueExact();
                    this.readState = ReadState.READ_OPERATION_TYPE;
                    break;
                case READ_OPERATION_TYPE:
                    if (!Asn1ReadResult.ReadType.OBJECT.equals(readResult.getReadType())) {
                        throw new IOException("Wrong payload order");
                    }
                    this.updateFingerprintPayload(readResult.getRawBuffer());
                    this.operationType = OperationType.valueOf(ASN1Enumerated.getInstance(readResult.getObject()).intValueExact());
                    this.readState = ReadState.READING_HEADER;
                    break;
                case READING_HEADER:
                    if (!Asn1ReadResult.ReadType.OBJECT.equals(readResult.getReadType())) {
                        throw new IOException("Wrong payload order");
                    }
                    this.processChunk(readResult);
                    break;
            }
        }
        return 0;
    }

    @Override
    public boolean isDataReadable() {
        return this.readState.ordinal() >= ReadState.DATA_PENDING.ordinal();
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
        int headerReadResult = headerRead();
        int readSize = 0;
        if (headerReadResult != 0) {
            return 0;
        }

        if (this.readState.ordinal() <= ReadState.DATA_PENDING.ordinal()) {
            if (this.initBasic()) {
                this.prepareReadData();
            }
        }

        if(this.plainDataQueue.isEmpty()) {
            Asn1ReadResult readResult;
            do {
                readResult = this.asn1StreamReader.readObject(true);
                if (readResult != null) {
                    if (Asn1ReadResult.ReadType.END_SEQUENCE.equals(readResult.getReadType())) {
                        this.readState = ReadState.END_SEQUENCE;
                        validate();
                    } else {
                        this.processChunk(readResult);
                    }
                }
            } while (this.plainDataQueue.isEmpty() && (readResult != null));
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
                if(ReadState.END_SEQUENCE.equals(this.readState)) {
                    return -1;
                }
            }
        }

        return readSize;
    }

    private void parseUserChunks() throws IOException {
        if(!this.authKeyValidated) {
            throw new IOException(new IllegalStateException("user chunks not readable yet"));
        }
        if (this.cachedUserChunks != null) {
            return ;
        }
        Map<Integer, UserChunk> map = new HashMap<>();
        for(Map.Entry<Integer, Asn1ObjectChunkBase> entry : this.chunkMap.entrySet()) {
            if (entry.getKey() >= ChunkId.CustomBegin.getValue()) {
                Asn1CustomDataChunk customDataChunk = (Asn1CustomDataChunk)entry.getValue();
                //int flag, int userCode, int dataSize, byte[] data
                UserChunk.Builder builder = UserChunk.builder();
                if(customDataChunk.getFlags().isEncryptWithAuthKey()) {
                    builder.encryptWithAuthKey();
                }
                byte[] data = customDataChunk.getBytesData();
                builder
                        .withUserCode(entry.getKey() - ChunkId.CustomBegin.getValue())
                        .withDataSize(data.length)
                        .withData(data);
                map.put(entry.getKey() - ChunkId.CustomBegin.getValue(), builder.build());
            }
        }
        this.cachedUserChunks = Collections.unmodifiableMap(map);
    }

    public TimeStampToken getTimestampToken() throws IOException, TSPException {
        Asn1TimestampChunk timestampChunk = this.getChunk(Asn1TimestampChunk.class, Asn1TimestampChunk.CHUNK_ID);
        if (timestampChunk == null) {
            return null;
        }
        return new TimeStampToken(timestampChunk.getData());
    }

    @Override
    public Enumeration<UserChunk> userChunks() throws IOException {
        parseUserChunks();
        return Collections.enumeration(this.cachedUserChunks.values());
    }

    @Override
    public UserChunk getUserChunk(short code) throws IOException {
        parseUserChunks();
        return this.cachedUserChunks.get((int)code);
    }

    @Override
    public void validate() throws IOException {
        if(this.readState.ordinal() < ReadState.END_SEQUENCE.ordinal()) {
            throw new IOException("Can not validate yet");
        }
        Asn1FingerprintChunk fingerprintChunk = this.getChunk(Asn1FingerprintChunk.class, Asn1FingerprintChunk.CHUNK_ID);
        if (!Arrays.equals(fingerprintChunk.getBytesData(), this.computedFingerprint)) {
            ValidateFailedException exception = new ValidateFailedException("Incorrect fingerprint");
            this.validateException = exception;
            throw exception;
        }
        if (this.validateException != null) {
            throw validateException;
        }
        try {
            if (OperationType.SIGN.equals(this.operationType)) {
                Asn1SignedFingerprintChunk signedFingerprintChunk = this.getChunk(Asn1SignedFingerprintChunk.class, Asn1SignedFingerprintChunk.CHUNK_ID);
                if (!this.asymKey.verify(
                        new AlgorithmIdentifier(
                                this.fingerprintAlgorithm.getOid()
                        ),
                        this.computedFingerprint,
                        signedFingerprintChunk.getBytesData()
                )) {
                    ValidateFailedException exception = new ValidateFailedException("Incorrect signature");
                    this.validateException = exception;
                    throw exception;
                }
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new IOException(e);
        }
    }
}
