import kr.jclab.javautils.asymsecurefile.*;
import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class Jasf3ECKeyTest {
    private final KeyPair keyPair;
    private final KeyPair tempRsaKeyPair;
    private final KeyPair tempEcKeyPair;

    public Jasf3ECKeyTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        PrivateKey ecPrivateKey = TestUtils.parsePrivateKeyPem("-----BEGIN PRIVATE KEY-----\n" +
                "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1\n" +
                "q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/\n" +
                "k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI\n" +
                "-----END PRIVATE KEY-----");
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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.SIGN, bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPrivate())
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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.SIGN, bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPrivate())
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
    public void signAndVerifyWithUserChunkTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.SIGN, bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPrivate())
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

            {
                UserChunk userChunk = inputStream.getUserChunk((short)0x01);
                assert "I_AM_NORMAL-1".equals(new String(userChunk.getData()));
            }
            {
                UserChunk userChunk = inputStream.getUserChunk((short)0x02);
                assert "I_AM_SECRET-1".equals(new String(userChunk.getData()));
            }

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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.SIGN, bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPrivate())
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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.SIGN, bos)
                    .securityProvider(securityProvider)
                    .authKey("1234")
                    .excludeHeader(false)
//                    .enableTimestamping("http://tsa.starfieldtech.com")
                    .asymKey(this.keyPair.getPrivate())
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

    @Test
    public void justPublicEncryptTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.PUBLIC_ENCRYPT, bos)
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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.PUBLIC_ENCRYPT, bos)
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
            inputStream.setAsymKey(this.keyPair.getPrivate());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test
    public void publicEncryptAndDecryptWithUserChunksTest() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.PUBLIC_ENCRYPT, bos)
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
            inputStream.setAsymKey(this.keyPair.getPrivate());

            {
                UserChunk userChunk = inputStream.getUserChunk((short)0x01);
                assert "I_AM_NORMAL-1".equals(new String(userChunk.getData()));
            }
            {
                UserChunk userChunk = inputStream.getUserChunk((short)0x02);
                assert "I_AM_SECRET-1".equals(new String(userChunk.getData()));
            }

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
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.PUBLIC_ENCRYPT, bos)
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
            inputStream.setAsymKey(this.keyPair.getPrivate());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test(expected = IOException.class)
    public void publicEncryptAndDecryptWithWrongAsymKeySameAlgoShouldFail() throws IOException {
        final Provider securityProvider = new BouncyCastleProvider();
        byte[] signedPayload;

        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream.Builder(AsymSecureFileVersion.JASF_3, OperationType.PUBLIC_ENCRYPT, bos)
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
            inputStream.setAsymKey(this.tempEcKeyPair.getPrivate());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }
}
