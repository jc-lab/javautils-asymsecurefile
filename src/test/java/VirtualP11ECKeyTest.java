import kr.jclab.javautils.asymsecurefile.AsymSecureFileInputStream;
import kr.jclab.javautils.asymsecurefile.AsymSecureFileOutputStream;
import kr.jclab.javautils.asymsecurefile.UserChunk;
import kr.jclab.javautils.asymsecurefile.ValidateFailedException;
import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

/*
 * If non-exportable private key, should use key pair to asymKey.
 */
public class VirtualP11ECKeyTest {
    private final KeyPair keyPair;
    private final KeyPair tempRsaKeyPair;
    private final KeyPair tempEcKeyPair;

    public static class VirtualP11ECPrivateKey extends BCECPrivateKey {
        private final BCECPrivateKey originalKey;

        public VirtualP11ECPrivateKey(BCECPrivateKey originalKey) {
            this.originalKey = originalKey;
        }

        @Override
        public String getAlgorithm() {
            return this.originalKey.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }

        @Override
        public ECParameterSpec getParams() {
            return this.originalKey.getParams();
        }

        @Override
        public org.bouncycastle.jce.spec.ECParameterSpec getParameters() {
            return this.originalKey.getParameters();
        }

        @Override
        public BigInteger getS() {
            return this.originalKey.getS();
        }

        @Override
        public BigInteger getD() {
            return this.originalKey.getD();
        }

        @Override
        public void setBagAttribute(ASN1ObjectIdentifier asn1ObjectIdentifier, ASN1Encodable asn1Encodable) {
            this.originalKey.setBagAttribute(asn1ObjectIdentifier, asn1Encodable);
        }

        @Override
        public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier asn1ObjectIdentifier) {
            return this.originalKey.getBagAttribute(asn1ObjectIdentifier);
        }

        @Override
        public Enumeration getBagAttributeKeys() {
            return this.originalKey.getBagAttributeKeys();
        }

        @Override
        public void setPointFormat(String s) {
            this.originalKey.setPointFormat(s);
        }

        @Override
        public boolean equals(Object o) {
            return this.originalKey.equals(o);
        }

        @Override
        public int hashCode() {
            return this.originalKey.hashCode();
        }

        @Override
        public String toString() {
            return this.originalKey.toString();
        }
    }

    public VirtualP11ECKeyTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        PrivateKey ecPrivateKey = new VirtualP11ECPrivateKey((BCECPrivateKey)TestUtils.parsePrivateKeyPem("-----BEGIN PRIVATE KEY-----\n" +
                "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1\n" +
                "q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/\n" +
                "k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI\n" +
                "-----END PRIVATE KEY-----"));
        PublicKey ecPublicKey = TestUtils.parsePublicKeyPem("-----BEGIN PUBLIC KEY-----\n" +
                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/\n" +
                "P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==\n" +
                "-----END PUBLIC KEY-----");
        this.keyPair = new KeyPair(ecPublicKey, ecPrivateKey);

        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BCProviderSingletone.getProvider());
            kpg.initialize(1024);
            this.tempRsaKeyPair = kpg.generateKeyPair();
        }
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BCProviderSingletone.getProvider());
            kpg.initialize(new ECGenParameterSpec("secp256k1"));
            this.tempEcKeyPair = kpg.generateKeyPair();
        }
    }

    @Test
    public void justSignTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair)
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));
    }

    @Test
    public void signAndVerifyTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair)
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.keyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test
    public void verifyWithPreGeneratedTest() throws IOException {
        {
            InputStream bis = this.getClass().getResourceAsStream("/pregenerated/ec-sign.jasf");
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.keyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void signAndVerifyWithWrongAuthKeyShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair)
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1111");
            inputStream.setAsymKey(this.keyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void signAndVerifyWithWrongAsymKeySameAlgoShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair)
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.tempEcKeyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void signAndVerifyWithWrongAsymKeyDiffAlgoShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair)
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.tempRsaKeyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test
    public void justPublicEncryptTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4PublicEncrypt(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPublic())
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));
    }

    @Test
    public void publicEncryptAndDecryptTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4PublicEncrypt(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPublic())
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.keyPair);
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test
    public void publicDecryptWithPreGeneratedTest() throws IOException {
        {
            InputStream bis = this.getClass().getResourceAsStream("/pregenerated/ec-pe.jasf");
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.keyPair);
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void publicEncryptAndDecryptWithWrongAuthKeyShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4PublicEncrypt(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPublic())
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("2345");
            inputStream.setAsymKey(this.keyPair);
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void publicEncryptAndDecryptWithWrongAsymKeySameAlgoShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4PublicEncrypt(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPublic())
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.tempEcKeyPair);
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = ValidateFailedException.class)
    public void publicEncryptAndDecryptWithWrongAsymKeyDiffAlgoShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4PublicEncrypt(bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPublic())
                    .build();

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x1)
                            .withData("I_AM_NORMAL-1".getBytes())
                            .build());
            outputStream.setUserChunk(
                    UserChunk.builder()
                            .withUserCode((short)0x2)
                            .withData("I_AM_SECRET-1".getBytes())
                            .withFlag(UserChunk.Flag.EncryptWithAuthKey)
                            .build());

            outputStream.write("HELLO WORLD,".getBytes());
            outputStream.write("I AM HAPPY".getBytes());

            outputStream.close();

            signedPayload = bos.toByteArray();
        }

        System.out.println(TestUtils.dump(signedPayload, false));

        {
            ByteArrayInputStream bis = new ByteArrayInputStream(signedPayload);
            AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] tempBuf = new byte[3];

            int r;
            while((r = inputStream.headerRead()) == 1) {
                System.out.println("Reading header...");
            }
            inputStream.setAuthKey("1234");
            inputStream.setAsymKey(this.tempRsaKeyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }
}
