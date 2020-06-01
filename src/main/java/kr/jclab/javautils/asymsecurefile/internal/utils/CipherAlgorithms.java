package kr.jclab.javautils.asymsecurefile.internal.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.*;
import java.util.function.Function;

public class CipherAlgorithms {
    public static final int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    public static final int DECRYPT_MODE = Cipher.DECRYPT_MODE;

    public static class CryptoParams {
        private final int mode;
        private final Provider securityProvider;
        private final byte[] iv;
        private final int authTagLength;

        public CryptoParams(int mode, Provider securityProvider, byte[] iv, int authTagLength) {
            this.mode = mode;
            this.securityProvider = securityProvider;
            this.iv = iv;
            this.authTagLength = authTagLength;
        }

        public int getMode() {
            return mode;
        }

        public Provider getSecurityProvider() {
            return securityProvider;
        }

        public byte[] getIv() {
            return iv;
        }

        public int getAuthTagLength() {
            return authTagLength;
        }

        public static Builder builder(int mode) {
            return new Builder(mode);
        }

        public static class Builder {
            private final int mode;
            private Provider securityProvider;
            private byte[] iv;
            private int authTagLength = 0;

            public Builder(int mode) {
                this.mode = mode;
            }

            public Builder securityProvider(Provider provider) {
                this.securityProvider = securityProvider;
                return this;
            }

            public Builder iv(byte[] iv) {
                this.iv = iv;
                return this;
            }

            public Builder authTagLength(int authTagLength) {
                this.authTagLength = authTagLength;
                return this;
            }

            public CryptoParams build() {
                return new CryptoParams(this.mode, this.securityProvider, this.iv, this.authTagLength);
            }
        }
    }

    public static class CreateCipherResult {
        private final CryptoParams cryptoParams;
        private final Cipher cipher;

        public CreateCipherResult(CryptoParams cryptoParams, Cipher cipher) {
            this.cryptoParams = cryptoParams;
            this.cipher = cipher;
        }

        public CryptoParams getParams() {
            return cryptoParams;
        }

        public Cipher getCipher() {
            return cipher;
        }
    }

    public static class AlgorithmEntry {
        private final String name;
        private final String cipherName;
        private final ASN1ObjectIdentifier oid;
        private final int keySize;
        private final boolean isGcmMode;
        private final Function<CryptoParams, CreateCipherResult> cipherSupplier;

        public AlgorithmEntry(String name, String cipherName, ASN1ObjectIdentifier oid, int keySize, boolean isGcmMode, Function<CryptoParams, CreateCipherResult> cipherSupplier) {
            this.name = name;
            this.cipherName = cipherName;
            this.oid = oid;
            this.keySize = keySize;
            this.isGcmMode = isGcmMode;
            this.cipherSupplier = cipherSupplier;
        }

        public String getName() {
            return name;
        }

        public String getCipherName() {
            return cipherName;
        }

        public ASN1ObjectIdentifier getOid() {
            return oid;
        }

        public int getKeySize() {
            return keySize;
        }

        public boolean isGcmMode() {
            return isGcmMode;
        }

        public Function<CryptoParams, CreateCipherResult> getCipherSupplier() {
            return cipherSupplier;
        }

        public CreateCipherResult createCipher(CryptoParams params, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
            CreateCipherResult result;
            if (this.cipherSupplier != null) {
                result = this.cipherSupplier.apply(params);
            } else {
                Cipher cipher;
                if (params.getSecurityProvider() != null) {
                    cipher = Cipher.getInstance(this.cipherName, params.getSecurityProvider());
                } else {
                    cipher = Cipher.getInstance(this.cipherName);
                }
                int authTagLength = params.getAuthTagLength() <= 0 ? 12 : params.getAuthTagLength();
                byte[] iv = params.getIv();
                if(iv == null) {
                    iv = new byte[cipher.getBlockSize()];
                    SingletoneHolder.RANDOM.nextBytes(iv);
                }
                if(this.isGcmMode) {
                    cipher.init(params.getMode(), new SecretKeySpec(key, "AES"), new GCMParameterSpec(authTagLength * 8, iv));
                }else{
                    cipher.init(params.getMode(), new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                }
                result = new CreateCipherResult(
                        new CryptoParams(params.getMode(), params.getSecurityProvider(), iv, authTagLength),
                        cipher
                );
            }
            return result;
        }
    }

    public static AlgorithmEntry findByName(String name) {
        return SingletoneHolder.NAME_MAP.get(name);
    }

    public static AlgorithmEntry findByOid(String oid) {
        return SingletoneHolder.OID_MAP.get(oid);
    }

    public static AlgorithmEntry findByOid(ASN1ObjectIdentifier oid) {
        return SingletoneHolder.OID_MAP.get(oid.getId());
    }

    private static class SingletoneHolder {
        private static Map<String, AlgorithmEntry> NAME_MAP;
        private static Map<String, AlgorithmEntry> OID_MAP;
        private static SecureRandom RANDOM = new SecureRandom();

        static {
            final List<AlgorithmEntry> entries = Arrays.asList(
                    new AlgorithmEntry(
                            "aes-128-cbc",
                            "AES/CBC/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes128_CBC,
                            128,
                            false,
                            null
                    ),
                    new AlgorithmEntry(
                            "aes-192-cbc",
                            "AES/CBC/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes192_CBC,
                            192,
                            false,
                            null
                    ),
                    new AlgorithmEntry(
                            "aes-256-cbc",
                            "AES/CBC/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes256_CBC,
                            256,
                            false,
                            null
                    ),
                    new AlgorithmEntry(
                            "aes-128-gcm",
                            "AES/GCM/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes128_GCM,
                            128,
                            true,
                            null
                    ),
                    new AlgorithmEntry(
                            "aes-192-gcm",
                            "AES/GCM/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes192_GCM,
                            192,
                            true,
                            null
                    ),
                    new AlgorithmEntry(
                            "aes-256-gcm",
                            "AES/GCM/PKCS5Padding",
                            NISTObjectIdentifiers.id_aes256_GCM,
                            256,
                            true,
                            null
                    )
            );
            NAME_MAP = Collections.unmodifiableMap(new HashMap<String, AlgorithmEntry>() {{
                for(AlgorithmEntry entry : entries) {
                    put(entry.getName(), entry);
                }
            }});
            OID_MAP = Collections.unmodifiableMap(new HashMap<String, AlgorithmEntry>() {{
                for(AlgorithmEntry entry : entries) {
                    put(entry.getOid().toString(), entry);
                }
            }});
        }
    }
}
