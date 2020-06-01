import kr.jclab.javautils.asymsecurefile.AsymSecureFileInputStream;
import kr.jclab.javautils.asymsecurefile.AsymSecureFileOutputStream;
import kr.jclab.javautils.asymsecurefile.UserChunk;
import kr.jclab.javautils.asymsecurefile.ValidateFailedException;
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

public class RSAKeyTest {
    private final KeyPair keyPair;

    private final KeyPair tempRsaKeyPair;
    private final KeyPair tempEcKeyPair;

    public RSAKeyTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        PrivateKey rsaPrivateKey = TestUtils.parsePrivateKeyPem("-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv\n" +
                "cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj\n" +
                "PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB\n" +
                "AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy\n" +
                "WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z\n" +
                "8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr\n" +
                "t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx\n" +
                "VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0\n" +
                "VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G\n" +
                "SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL\n" +
                "p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby\n" +
                "Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN\n" +
                "s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=\n" +
                "-----END RSA PRIVATE KEY-----");
        PublicKey rsaPublicKey = TestUtils.parsePublicKeyPem("-----BEGIN PUBLIC KEY-----\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5\n" +
                "ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s\n" +
                "SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0\n" +
                "N1JinKuM1XYpyKvqlQIDAQAB\n" +
                "-----END PUBLIC KEY-----");
        this.keyPair = new KeyPair(rsaPublicKey, rsaPrivateKey);

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
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
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
    public void verifyWithPreGeneratedTest() throws IOException {
        {
            InputStream bis = this.getClass().getResourceAsStream("/pregenerated/rsa-sign.jasf");
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
            AsymSecureFileOutputStream outputStream = AsymSecureFileOutputStream.jasf4Sign(bos)
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
            inputStream.setAsymKey(this.tempRsaKeyPair.getPublic());
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
            inputStream.setAsymKey(this.keyPair.getPrivate());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }

    @Test
    public void publicDecryptWithPreGeneratedTest() throws IOException {
        {
            InputStream bis = this.getClass().getResourceAsStream("/pregenerated/rsa-pe.jasf");
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
            inputStream.setAsymKey(this.keyPair.getPrivate());
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
            inputStream.setAsymKey(this.tempRsaKeyPair.getPrivate());
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
            inputStream.setAsymKey(this.tempEcKeyPair.getPublic());
            while((r = inputStream.read(tempBuf)) > 0) {
                bos.write(tempBuf, 0, r);
            }

            assert new String(bos.toByteArray()).equals("HELLO WORLD,I AM HAPPY");
        }
    }
}
