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
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

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
        INIT,
        INITED,
        WRITE_HEADER,
        WRITE_DATA,
        WRITE_FOOTER;
    }

    private final Random random = new SecureRandom();
    private final BouncyCastleProvider workSecurityProvider = new BouncyCastleProvider();

    private AlgorithmInfo algorithmInfo = null;
    private transient Key asymKey = null;
    private transient PrivateKey localPrivateKey = null;
    private DataAlgorithm dataAlgorithm = null;
    private int dataChunkSize = 4096;

    private State state = State.INIT;

    /**
     * < 0x80 : Jasf Header
     * 0x80 0000 ~ 0x80 FFFF : User Chunk
     */
    private final Map<Integer, Chunk> rawChunkMap = new HashMap<>();

    private final DefaultHeaderChunk defaultHeaderChunk;

    private transient byte[] authKey = null;
    private transient byte[] authEncKey = null;

    private transient byte[] macKey = null;
    private transient Cipher dataCipher = null;
    private transient MessageDigest fingerprintDigest = null;

    private ByteArrayOutputStream writingDataTempBuffer = null;

    public Jasf3OutputStreamDelegate(OperationType operationType, OutputStream outputStream, Provider securityProvider) {
        super(operationType, outputStream, securityProvider);
        this.defaultHeaderChunk = DefaultHeaderChunk.builder().withOperationType(operationType).build(this.random);
    }

    @Override
    public void init(Key key, AsymAlgorithm asymAlgorithm, DataAlgorithm dataAlgorithm, byte[] authKey, PrivateKey localPrivateKey) throws IOException {
        if(state != State.INIT)
            return ;

        this.algorithmInfo = new AlgorithmInfo(key, asymAlgorithm);
        if(this.algorithmInfo.getAlgorithm() == null) {
            throw new NotSupportAlgorithmException();
        }
        this.asymKey = key;
        this.localPrivateKey = localPrivateKey;
        this.authKey = authKey;
        this.dataAlgorithm = dataAlgorithm;
        setRawChunk(AsymAlgorithmChunk.builder().withAlgorithmInfo(this.algorithmInfo).build());

        // ========== Generate SeedKey and DataKey & Store to chunk ==========

        try {
            byte[] dataKey;

            byte[] dataIV = new byte[16];
            EncryptedSeedKeyChunk.Builder encryptedSeedKeyChunkBuilder = EncryptedSeedKeyChunk.builder();
            this.random.nextBytes(dataIV);

            // AuthEncKey = HmacSHA256(authKey, DefaultHeader.seed)
            Mac authEncKeyMac = Mac.getInstance("HmacSHA256");
            authEncKeyMac.init(new SecretKeySpec(this.authKey, authEncKeyMac.getAlgorithm()));
            this.authEncKey = authEncKeyMac.doFinal(this.defaultHeaderChunk.seed());

            // dataKey
            // * PUBLIC_ENCRYPT : HmacSHA256(authKey, ECDH_shared_key / RSA Encrypted Seed Key)
            // * SIGN : same to authEncKey

            if(this.operationType == OperationType.PUBLIC_ENCRYPT) {
                byte[] seedKey;
                Mac dataKeyMac = Mac.getInstance("HmacSHA512", this.workSecurityProvider);
                dataKeyMac.init(new SecretKeySpec(this.authKey, dataKeyMac.getAlgorithm()));

                if ((this.algorithmInfo.getAlgorithm() == AsymAlgorithm.EC) || (this.algorithmInfo.getAlgorithm() == AsymAlgorithm.PRIME)) {
                    // Like ECIES
                    KeyPair localKeyPair;
                    if(this.localPrivateKey != null) {
                        ECPrivateKey ecLocalPrivateKey = (ECPrivateKey)this.localPrivateKey;
                        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", this.securityProvider);
                        ECParameterSpec ecSpec = EC5Util.convertSpec(ecLocalPrivateKey.getParams(), false);
                        ECPoint Q = ecSpec.getG().multiply(ecLocalPrivateKey.getS());
                        byte[] publicDerBytes = Q.getEncoded(false);
                        ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
                        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
                        ECPublicKey publicKeyGenerated = (ECPublicKey) keyFactory.generatePublic(pubSpec);
                        localKeyPair = new KeyPair(publicKeyGenerated, this.localPrivateKey);
                    }else{
                        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.algorithmInfo.getAlgorithm().getAlgorithm());
                        keyPairGenerator.initialize(((ECKey)this.asymKey).getParams());
                        localKeyPair = keyPairGenerator.generateKeyPair();
                    }
                    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", this.workSecurityProvider);;
                    keyAgreement.init(localKeyPair.getPrivate());
                    keyAgreement.doPhase(this.asymKey, true);
                    encryptedSeedKeyChunkBuilder.withData(localKeyPair.getPublic().getEncoded());
                    seedKey = keyAgreement.generateSecret();
                } else if (this.algorithmInfo.getAlgorithm() == AsymAlgorithm.RSA) {
                    Cipher seedKeyCipher = Cipher.getInstance("RSA/ECB/OAEPPadding", this.securityProvider);
                    seedKey = new byte[32];
                    this.random.nextBytes(seedKey);
                    seedKeyCipher.init(Cipher.ENCRYPT_MODE, this.asymKey);
                    encryptedSeedKeyChunkBuilder.withData(seedKeyCipher.doFinal(seedKey));
                } else {
                    throw new RuntimeException("Unknown AsymKey Type");
                }
                byte[] bigKey = dataKeyMac.doFinal(seedKey);
                dataKey = Arrays.copyOfRange(bigKey, 0, 32);
                this.macKey = Arrays.copyOfRange(bigKey, 32, 64);
                setRawChunk(SeedKeyCheckChunk.builder(this.random).withPlainKey(seedKey).build());
                setRawChunk(encryptedSeedKeyChunkBuilder.build());
            }else if(this.operationType == OperationType.SIGN) {
                dataKey = this.authEncKey;
                this.macKey = this.authKey;
            }else{
                throw new RuntimeException("Unknown error");
            }

            int dataKeySize = this.dataAlgorithm.getKeySize();
            if (dataKeySize != dataKey.length) {
                if (dataKeySize > dataKey.length) {
                    dataKey = Arrays.copyOf(dataKey, dataKeySize);
                } else {
                    throw new RuntimeException("Not support key size = " + (dataKeySize * 8));
                }
            }

            this.fingerprintDigest = MessageDigest.getInstance("SHA-256", this.workSecurityProvider);
            this.dataCipher = createDataCipher(dataIV, dataKey, this.macKey);
            dataIV = this.dataCipher.getIV();

            setRawChunk(DataAlgorithmChunk.builder().withDataAlgorithm(this.dataAlgorithm).build());
            setRawChunk(DataIvChunk.builder().withIv(dataIV).build());
        } catch (Exception e) {
            throw new IOException(e);
        }

        // ========== prepare WriteData =========
        this.setRawChunk(this.defaultHeaderChunk);

        this.state = State.INITED;
    }

    @Override
    public void setUserChunk(UserChunk chunk) throws IOException {
        if(this.state != State.INITED) {
            throw new IllegalStateException();
        }
        if(chunk.getFlag() == Chunk.Flag.EncryptedWithAuthEncKey) {
            byte[] dataIV = new byte[16];
            this.random.nextBytes(dataIV);
            try {
                Cipher cipher = createChunkCipher(dataIV, this.authEncKey, this.authKey);
                byte[] ciphertext = cipher.doFinal(chunk.getData(), 0, chunk.getDataSize());
                byte[] buffer = new byte[16 + ciphertext.length];
                System.arraycopy(dataIV, 0, buffer, 0, dataIV.length);
                System.arraycopy(ciphertext, 0, buffer, dataIV.length, ciphertext.length);
                this.rawChunkMap.put(0x800000 | chunk.getUserCode(), new RawChunk((byte)(0x80 | chunk.getFlag().value()), chunk.getUserCode(),  (short)buffer.length, buffer));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                throw new IOException(e);
            }
        }else{
            this.rawChunkMap.put(chunk.getChunkId(), chunk);
        }
    }

    @Override
    public void write(byte[] buffer, int off, int size) throws IOException {
        if(this.state == State.INITED) {
            this.state = State.WRITE_HEADER;
            writeHeader();
        }else if(this.state == State.WRITE_HEADER) {
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
                if(writingDataTempBuffer.size() > 0) {
                    ciphertext = dataCipher.doFinal(this.writingDataTempBuffer.toByteArray(), 0, this.writingDataTempBuffer.size());
                }else{
                    ciphertext = dataCipher.doFinal();
                }
                writeRawChunk(new RawChunk(Jasf3ChunkType.DATA_STREAM.value(), (short)0, (short)ciphertext.length, ciphertext));
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
        byte[] fingerprint = this.fingerprintDigest.digest();
        FooterChunk.Builder footerChunkBuilder = FooterChunk.builder()
                .withFingerprint(fingerprint)
                .withTotalFileSizeWithoutFooter(this.getWrittenBytes());
        try {
            if(this.operationType == OperationType.SIGN) {
                footerChunkBuilder.withSignature(signData(fingerprint));
            }else{
                Mac mac = Mac.getInstance("HmacSHA256", this.workSecurityProvider);
                mac.init(new SecretKeySpec(this.macKey, mac.getAlgorithm()));
                mac.update(fingerprint);
                footerChunkBuilder.withMac(mac.doFinal());
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
        writeRawChunk(footerChunkBuilder.build());
        outputStream.flush();
    }

    private byte[] signData(byte[] data) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        // Sign
        Signature signature = Signature.getInstance(this.algorithmInfo.getAlgorithm().getSignatureAlgorithm(), this.securityProvider);
        signature.initSign((PrivateKey) this.asymKey);
        signature.update(data);
        return signature.sign();
    }

    private Cipher createDataCipher(byte[] dataIv, byte[] key, byte[] macKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(this.dataAlgorithm.getIdentifier().getId(), this.workSecurityProvider);
        }catch (NoSuchAlgorithmException algoException) {
            cipher = Cipher.getInstance(this.dataAlgorithm.getAlgorithm(), this.workSecurityProvider);
        }
        if(this.dataAlgorithm.isContainMac()) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, dataIv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, this.dataAlgorithm.getAlgorithm().split("/", 2)[0]), gcmParameterSpec);
            cipher.updateAAD(macKey);
        }else{
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, this.dataAlgorithm.getAlgorithm().split("/", 2)[0]), new IvParameterSpec(dataIv));
        }
        return cipher;
    }

    private Cipher createChunkCipher(byte[] dataIV, byte[] key, byte[] authKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", this.workSecurityProvider);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, dataIV);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), gcmParameterSpec);
        cipher.updateAAD(authKey);
        return cipher;
    }
}
