/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4;

import kr.jclab.javautils.asymsecurefile.*;
import kr.jclab.javautils.asymsecurefile.internal.*;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.asn.*;
import kr.jclab.javautils.asymsecurefile.internal.utils.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class Jasf4OutputStreamDelegate extends OutputStreamDelegate {
    private enum WriteState {
        INITIALIZEING,
        WRITING_HEADER,
        WRITING_DATA,
        WRITING_FOOTER
    }

    private final SecureRandom random = new SecureRandom();
    private final BouncyCastleProvider workSecurityProvider = BCProviderSingletone.getProvider();

    private WriteState writeState = WriteState.INITIALIZEING;

    private final ASN1ObjectIdentifier chunkCryptoAlgorithm = NISTObjectIdentifiers.id_aes256_CBC;
    private final ASN1ObjectIdentifier fingerprintAlgorithm = NISTObjectIdentifiers.id_sha256;

    private Jasf4AuthKeyUtils.DerivedKeys authKeyDerivedKeys = null;
    private byte[] authKeyCryptoIv = null;

    private CipherAlgorithms.AlgorithmEntry dataCryptoAlgorithm = null;
    private Cipher dataCipher = null;
    private Mac dataMac = null;
    private MessageDigest fingerprintDigest = null;

    public Jasf4OutputStreamDelegate(OutputStreamOptions options) {
        super(options);
    }

    @Override
    public void init() throws IOException {
        if(writeState != WriteState.INITIALIZEING)
            return ;

        ASN1ObjectIdentifier dataMacAlgorithm = null;

        try {
            byte[] dataIv = new byte[16];
            byte[] dataCryptoKey;
            byte[] dataMacKey;

            this.random.nextBytes(dataIv);

            this.authKeyCryptoIv = new byte[16];
            this.random.nextBytes(authKeyCryptoIv);

            this.fingerprintDigest = MessageDigest.getInstance(this.fingerprintAlgorithm.getId(), this.workSecurityProvider);

            this.authKeyDerivedKeys = Jasf4AuthKeyUtils.deriveKeys(this.options.getAuthKey());

            if(!this.options.isExcludeHeader()) {
                outputStream.write(SignatureHeader.SIGNATURE);
                outputStream.write(AsymSecureFileVersion.JASF_4_1.getVersion());
            }

            // file header payload
            {
                ASN1Integer version = new ASN1Integer(this.options.getVersion().getVersion());
                ASN1Enumerated operationType = new ASN1Enumerated(this.operationType.value());
                this.writePayload(new byte[] { (byte)0x30 , (byte)0x80 });
                this.writePayload(version.getEncoded());
                this.writePayload(operationType.getEncoded());
            }

            Asn1ObjectChunkBase dataKeyInfoChunk = null;
            Asn1EphemeralECPublicKeyChunk ephemeralECPublicKeyChunk = null;
            Asn1DHCheckDataChunk dhCheckDataChunk = null;
            Asn1DataCryptoAlgorithmParameterSpecChunk dataCryptoAlgorithmParameterSpecChunk = null;

            if (OperationType.SIGN.equals(this.options.getOperationType()) || this.options.getAsymKey().isPublicEncryptable()) {
                dataCryptoKey = new byte[32];
                dataMacKey = new byte[32];
                this.random.nextBytes(dataCryptoKey);
                this.random.nextBytes(dataMacKey);
                Asn1DataKeyInfoChunk plainDataKeyInfoChunk = new Asn1DataKeyInfoChunk(dataCryptoKey, dataMacKey);
                if (this.options.getAsymKey().isPublicEncryptable()) {
//                    byte[] ciphertext = this.options.getAsymKey().publicEncrypt(plainDataKeyInfoChunk.getEncoded());
                    byte[] ciphertext = this.options.getAsymKey().publicEncrypt(plainDataKeyInfoChunk.dataToASN1Primitive().getEncoded());
                    dataKeyInfoChunk = new Asn1EncryptedDataKeyInfoChunk(ciphertext);
                }else{
                    dataKeyInfoChunk = plainDataKeyInfoChunk;
                }
            }else{
                KeyPair ephemeralKeyPair = this.options.getAsymKey().generateKeyPair();
                AsymmetricKeyObject ephemeralPrivateKey = AsymmetricKeyObject.fromKey(ephemeralKeyPair.getPrivate(), this.options.getAsymKey().getSecurityProvider());
                KeyAgreement keyAgreement = ephemeralPrivateKey.createKeyAgreement();
                keyAgreement.doPhase(this.options.getAsymKey().getKey(), true);
                byte[] hkdfResult = HkdfUtils.generateKey(
                        HashAlgorithms.findByOid(NISTObjectIdentifiers.id_sha256),
                        keyAgreement.generateSecret(),
                        96,
                        null
                );

                dataCryptoKey = Arrays.copyOfRange(hkdfResult, 0, 32);
                dataMacKey = Arrays.copyOfRange(hkdfResult, 32, 64);
                dataKeyInfoChunk = new Asn1DataKeyInfoChunk(dataCryptoKey, dataMacKey);
                ephemeralECPublicKeyChunk = new Asn1EphemeralECPublicKeyChunk(SubjectPublicKeyInfo.getInstance(
                        ASN1Sequence.getInstance(ephemeralKeyPair.getPublic().getEncoded())
                ));
                dhCheckDataChunk = new Asn1DHCheckDataChunk(Arrays.copyOfRange(hkdfResult, 64, 96));
            }


            this.dataCryptoAlgorithm = OperationType.PUBLIC_ENCRYPT.equals(options.getOperationType()) ?
                    CipherAlgorithms.findByOid(NISTObjectIdentifiers.id_aes256_GCM) :
                    CipherAlgorithms.findByOid(NISTObjectIdentifiers.id_aes256_CBC);

            CipherAlgorithms.CreateCipherResult createCipherResult = this.dataCryptoAlgorithm.createCipher(
                    CipherAlgorithms.CryptoParams.builder(CipherAlgorithms.ENCRYPT_MODE)
                            .iv(dataIv)
                            .authTagLength(12)
                            .build(),
                    dataCryptoKey
            );
            this.dataCipher = createCipherResult.getCipher();
            if (this.dataCryptoAlgorithm.isGcmMode()) {
                dataCryptoAlgorithmParameterSpecChunk = new Asn1DataCryptoAlgorithmParameterSpecChunk<>(
                        Asn1GcmParameters.class,
                        Asn1GcmParameters::getInstance,
                        new Asn1GcmParameters(
                                createCipherResult.getParams().getIv(),
                                createCipherResult.getParams().getAuthTagLength()
                        )
                );
            }else{
                dataCryptoAlgorithmParameterSpecChunk = new Asn1DataCryptoAlgorithmParameterSpecChunk<>(
                        ASN1OctetString.class,
                        ASN1OctetString::getInstance,
                        new DEROctetString(createCipherResult.getParams().getIv())
                );
            }

            if (OperationType.PUBLIC_ENCRYPT.equals(options.getOperationType())) {
                if(this.dataCryptoAlgorithm.isGcmMode()) {
                    this.dataCipher.updateAAD(dataMacKey);
                    dataMacAlgorithm = new ASN1ObjectIdentifier("1.0.9797.3.4");
                    this.dataMac = null;
                }else{
                    dataMacAlgorithm = PKCSObjectIdentifiers.id_hmacWithSHA256;
                    this.dataMac = Mac.getInstance("HmacSHA256", this.workSecurityProvider);
                    this.dataMac.init(new SecretKeySpec(dataMacKey, "Hmac"));
                }
            }

            // write default header
            {
                Asn1DefaultHeaderChunk chunk = new Asn1DefaultHeaderChunk(
                        this.options.getVersion().getSubVersion(),
                        this.options.getAsymKey().getAlgorithmType(),
                        this.chunkCryptoAlgorithm,
                        this.dataCryptoAlgorithm.getOid(),
                        this.fingerprintAlgorithm,
                        this.authKeyCryptoIv
                );
                this.writeChunk(chunk);
            }

            // write auth key check data
            {
                Asn1AuthKeyCheckChunk chunk = Jasf4AuthKeyUtils.makeAuthKeyCheck(this.options.getAuthKey());
                this.writeChunk(chunk);
            }

            // write ec algorithm param
            if (AsymmetricAlgorithmType.ec.equals(this.options.getAsymKey().getAlgorithmType())) {
                Asn1AsymAlgorithmIdentifierChunk chunk = new Asn1AsymAlgorithmIdentifierChunk(this.options.getAsymKey().getAlgorithmIdentifier());
                this.writeChunk(chunk);
            }

            this.writeChunk(dataCryptoAlgorithmParameterSpecChunk);

            if (ephemeralECPublicKeyChunk != null) {
                this.writeChunk(ephemeralECPublicKeyChunk);
            }
            if (dhCheckDataChunk != null) {
                this.writeChunk(dhCheckDataChunk);
            }
            if (dataMacAlgorithm != null) {
                Asn1DataMacAlgorithmChunk chunk = new Asn1DataMacAlgorithmChunk(
                        new AlgorithmIdentifier(
                                dataMacAlgorithm,
                                null
                        )
                );
                this.writeChunk(chunk);
            }
            this.writeChunk(dataKeyInfoChunk);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }

        this.writeState = WriteState.WRITING_HEADER;
    }

    @Override
    public void setUserChunk(UserChunk chunk) throws IOException {
        if (this.writeState.ordinal() >= WriteState.WRITING_DATA.ordinal()) {
            throw new IOException(new IllegalStateException());
        }
        Asn1ChunkFlags flags = new Asn1ChunkFlags();

        if (chunk.hasFlag(UserChunk.Flag.EncryptWithAuthKey)) {
            flags.encryptWithAuthKey();
        }

        this.writeChunk(new Asn1CustomDataChunk(chunk.getUserCode(), flags, chunk.getData()));
    }

    private void writePayload(byte[] payload) throws IOException {
        if(this.fingerprintDigest != null) {
            this.fingerprintDigest.update(payload);
        }
        this.outputStream.write(payload);
    }

    private void writeChunk(Asn1ObjectChunkBase chunk) throws IOException {
        try {
            Asn1ObjectChunkBase rawChunk = chunk;
            if(chunk.getFlags().isEncryptWithAuthKey()) {
                CipherAlgorithms.CreateCipherResult cipherResult = CipherAlgorithms.findByOid(this.chunkCryptoAlgorithm).createCipher(
                        CipherAlgorithms.CryptoParams.builder(CipherAlgorithms.ENCRYPT_MODE)
                                .iv(this.authKeyCryptoIv)
                                .securityProvider(this.workSecurityProvider)
                                .build(),
                        this.authKeyDerivedKeys.encryptKey
                );
                rawChunk = Asn1EncryptedChunk.encryptChunk(chunk, cipherResult.getCipher());
            }
            this.writePayload(rawChunk.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void write(byte[] buffer, int off, int size) throws IOException {
        if(this.writeState == WriteState.WRITING_HEADER) {
            this.writeState = WriteState.WRITING_DATA;
        }
        if(this.writeState != WriteState.WRITING_DATA) {
            throw new IOException(new IllegalStateException());
        }

        byte[] encrypted = this.dataCipher.update(buffer, off, size);
        if(encrypted != null && encrypted.length > 0) {
            if (this.dataMac != null) {
                this.dataMac.update(encrypted);
            }
            this.writeChunk(new Asn1DataChunk(encrypted));
        }
    }

    @Override
    public void finish() throws IOException {
        if(this.writeState != WriteState.WRITING_FOOTER) {
            try {
                byte[] encrypted = this.dataCipher.doFinal();
                byte[] mac = null;
                if(this.dataCryptoAlgorithm.isGcmMode()) {
                    mac = Arrays.copyOfRange(encrypted, encrypted.length - 12, encrypted.length);
                    encrypted = Arrays.copyOfRange(encrypted, 0, encrypted.length - 12);
                }
                if (encrypted != null && encrypted.length > 0) {
                    if (this.dataMac != null) {
                        mac = this.dataMac.doFinal(encrypted);
                    }
                    this.writeChunk(new Asn1DataChunk(encrypted));
                }
                if(mac != null) {
                    this.writeChunk(new Asn1MacOfEncryptedDataChunk(mac));
                }
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new IOException(e);
            }
            writeFooter();
            this.writeState = WriteState.WRITING_FOOTER;
        }
        outputStream.flush();
    }

    private void writeFooter() throws IOException {
        byte[] fingerprint = this.fingerprintDigest.digest();
        this.fingerprintDigest = null;

        Asn1FingerprintChunk fingerprintChunk = new Asn1FingerprintChunk(fingerprint);
        this.writeChunk(fingerprintChunk);

        try {
            if (OperationType.SIGN.equals(this.options.getOperationType())) {
                byte[] signature = this.options.getAsymKey().sign(
                        new AlgorithmIdentifier(this.fingerprintAlgorithm),
                        fingerprint
                );
                Asn1SignedFingerprintChunk signedFingerprintChunk = new Asn1SignedFingerprintChunk(signature);
                this.writeChunk(signedFingerprintChunk);
            }

            if (this.options.isEnabledTimestamping()) {
                TimeStampToken timeStampToken = TimestampingUtils.sign(
                        this.random,
                        this.fingerprintAlgorithm,
                        fingerprint,
                        this.options.getTsaLocation(),
                        this.options.getTimestampingTimeout()
                );
                Asn1TimestampChunk timestampChunk = new Asn1TimestampChunk(timeStampToken.toCMSSignedData().toASN1Structure());
                this.writeChunk(timestampChunk);
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IOException(e);
        }

        this.writePayload(new byte[] { 0x00, 0x00 });
    }
}
