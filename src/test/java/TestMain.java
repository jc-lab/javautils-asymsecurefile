import kr.jclab.javautils.asymsecurefile.*;
import kr.jclab.javautils.asymsecurefile.internal.deprecated.Chunk;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Enumeration;

public class TestMain {
    private final Provider provider = new BouncyCastleProvider();

    public static String bytesToHex(byte[] bytes) {
        final char hexArray[] = "0123456789abcdef".toCharArray();
        StringBuilder stringBuilder = new StringBuilder();
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            if(stringBuilder.length() > 0)
                stringBuilder.append(",");
            stringBuilder.append("0x");
            stringBuilder.append(hexArray[v >>> 4]);
            stringBuilder.append(hexArray[v & 0xf]);
        }
        return stringBuilder.toString();
    }


    private KeyPair parsePrivateKey(InputStream inputStream, String passphrase) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException, OperatorCreationException, InvalidAlgorithmParameterException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
        PEMParser pemParser = new PEMParser(new InputStreamReader(inputStream));

        ASN1ObjectIdentifier curveOid = null;
        PrivateKeyInfo privateKeyInfo = null;
        PrivateKey privateKey = null;

        Object pemObject = pemParser.readObject();
        while(pemObject != null) {
            if(pemObject instanceof ASN1ObjectIdentifier) {
                curveOid = (ASN1ObjectIdentifier)pemObject;
            }else if (pemObject instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;
                PEMDecryptorProvider decryptorProvider = new BcPEMDecryptorProvider(passphrase.toCharArray());
                PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
                privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
            } else if (pemObject instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) pemObject;
            } else if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
                JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(provider);
                PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemObject;
                privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(jce.build(passphrase.toCharArray()));
            } else if (pemObject instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
                privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
            }
            if(privateKeyInfo != null) {
                privateKey = converter.getPrivateKey(privateKeyInfo);
            }

            pemObject = pemParser.readObject();
        }

        if(privateKey instanceof ECPrivateKey) {
            if(curveOid == null) {
                if(privateKeyInfo.getPrivateKeyAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) {
                    curveOid = (ASN1ObjectIdentifier)privateKeyInfo.getPrivateKeyAlgorithm().getParameters();
                }
            }
            X9ECParameters ecParameters = ECNamedCurveTable.getByOID(curveOid);
            String name = ECNamedCurveTable.getName(curveOid);
            ECPrivateKey keyImpl = (ECPrivateKey) privateKey;
            ECParameterSpec ecSpec = new ECNamedCurveParameterSpec(
                    name,
                    ecParameters.getCurve(),
                    ecParameters.getG(),
                    ecParameters.getN(),
                    ecParameters.getH(),
                    ecParameters.getSeed());

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", provider);

            ECPoint Q = ecSpec.getG().multiply(keyImpl.getD());
            byte[] publicDerBytes = Q.getEncoded(false);

            ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            return new KeyPair(keyFactory.generatePublic(pubSpec), privateKey);
        }else if(privateKey instanceof RSAPrivateKey) {
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)privateKey;
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
            return new KeyPair(publicKey, privateKey);
        }else{
            throw new RuntimeException("Unknown key spec: " + privateKey.getAlgorithm() + "," + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
        }
    }

//    public static void pkcs11Test() throws Exception {
//        Security.insertProviderAt(new BouncyCastleProvider(), 1);
//        SunPKCS11 securityProvider = new SunPKCS11("D:\\SoftHSM2\\java-softhsm.cfg");
//        KeyStore keyStore = KeyStore.getInstance("PKCS11", securityProvider);
//        keyStore.load(null, "123456".toCharArray());
//
//        Certificate certificate = keyStore.getCertificate("test-1");
//        Key key = keyStore.getKey("test-1", null);
//
//
//        // RSA Test
//        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.RSA.getAlgorithm(), securityProvider);
//        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.RSA.getAlgorithm());
//        //keyPairGenerator.initialize(1024);
//
//        // EC Test
//        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.EC.getAlgorithm(), securityProvider);
//        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.EC.getAlgorithm());
//        //keyPairGenerator.initialize(256);
//
//        //KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        KeyPair keyPair = new KeyPair(certificate.getPublicKey(), (PrivateKey)key);
//
//        //Key storedKey = keyStore.getKey("test-ec-1", null);
//
//
//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//
//        /*
//        // SignedSecureFileOutputStream test
//        try(SignedSecureFileOutputStream outputStream = new SignedSecureFileOutputStream(bos, keyPair.getPrivate(), "TEST")) {
//            for (int i = 0; i < 10000; i++) {
//                byte[] buf = new byte[] {10};
//                outputStream.write(buf);
//            }
//            outputStream.save();
//        }
//        */
//
//        // AsymSecureFileOutputStream test
//        try(AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream(OperationType.PUBLIC_ENCRYPT, bos, securityProvider)) {
//            outputStream.setAsymKey(keyPair);
//            outputStream.setAuthKey("TEST".getBytes());
//
//            outputStream.setUserChunk(
//                    UserChunk.builder()
//                            .withUserCode((short)1)
//                            .withFlag(Chunk.Flag.EncryptedWithAuthEncKey)
//                            .withData(new byte[] {0x10, 0x20, 0x30, 0x40, 0x50,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2})
//                            .build());
//
//            for (int i = 0; i < 5766; i++) {
//                outputStream.write(10);
//            }
//
//            outputStream.finish();
//        }
//
//        byte[] payload = bos.toByteArray();
//        try(AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(new ByteArrayInputStream(payload), securityProvider))
//        {
//            while(inputStream.headerRead() == 1)
//            {
//                System.out.println("continous head reading");
//            }
//
//            inputStream.setAuthKey("TEST".getBytes());
//            inputStream.setAsymKey(keyPair);
//
//            Enumeration<UserChunk> enumeration = inputStream.userChunks();
//            while (enumeration.hasMoreElements()) {
//                UserChunk userChunk = enumeration.nextElement();
//                System.out.println("userChunk : " + userChunk + " / " + userChunk.getDataSize() + " / " + bytesToHex(userChunk.getData()));
//            }
//
//            int readlen;
//            byte[] buffer = new byte[8192];
//            while((readlen = inputStream.read(buffer)) > 0) {
//                System.out.println("READLEN : " + readlen + " // " + bytesToHex(Arrays.copyOf(buffer, readlen)));
//            }
//
//        }
//
//        System.out.println("PAYLOAD : " + bytesToHex(payload));
//
//        securityProvider.logout();
//    }

    public static void normalTest() throws Exception {
        Provider securityProvider = new BouncyCastleProvider();

        // RSA Test
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.RSA.getAlgorithm(), securityProvider);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithmOld.RSA.getAlgorithm());
        keyPairGenerator.initialize(1024);

        // EC Test
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.EC.getAlgorithm(), securityProvider);
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymAlgorithm.EC.getAlgorithm());
        //keyPairGenerator.initialize(256);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //Key storedKey = keyStore.getKey("test-ec-1", null);


        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        /*
        // SignedSecureFileOutputStream test
        try(SignedSecureFileOutputStream outputStream = new SignedSecureFileOutputStream(bos, keyPair.getPrivate(), "TEST")) {
            for (int i = 0; i < 10000; i++) {
                byte[] buf = new byte[] {10};
                outputStream.write(buf);
            }
            outputStream.save();
        }
        */

        // AsymSecureFileOutputStream test
        try(AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream(OperationType.SIGN, bos, securityProvider)) {
            outputStream.setAsymKey(keyPair);
            outputStream.setAuthKey("TEST".getBytes());

            outputStream.enableTimestamping(true, "http://tsa.starfieldtech.com");

            outputStream.setUserChunk(
                    UserChunk.builder()
                            .encryptWithAuthKey()
                            .withData(new byte[] {0x10, 0x20, 0x30, 0x40, 0x50})
                            .build());

            for (int i = 0; i < 10000; i++) {
                outputStream.write(10);
            }

            outputStream.finish();
        }

        byte[] payload = bos.toByteArray();
        try(AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(new ByteArrayInputStream(payload), securityProvider))
        {
            while(inputStream.headerRead() == 1)
            {
                System.out.println("continous head reading");
            }

            inputStream.setAuthKey("TEST".getBytes());
            inputStream.setAsymKey(keyPair);
//            inputStream.headerRead()

            Enumeration<UserChunk> enumeration = inputStream.userChunks();
            while (enumeration.hasMoreElements()) {
                UserChunk userChunk = enumeration.nextElement();
                System.out.println("userChunk : " + userChunk + " / " + userChunk.getDataSize() + " / " + bytesToHex(userChunk.getData()));
            }

            int readlen;
            byte[] buffer = new byte[8192];
            while((readlen = inputStream.read(buffer)) > 0) {
                System.out.println("READLEN : " + readlen + " // " + bytesToHex(Arrays.copyOf(buffer, readlen)));
            }

        }

        System.out.println("PublicKey : " + bytesToHex(keyPair.getPublic().getEncoded()));

        System.out.println("PrivateKey : " + bytesToHex(keyPair.getPrivate().getEncoded()));

        System.out.println("PAYLOAD : " + bytesToHex(payload));
    }

    public void normalTest2() throws Exception {
        if(true) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (AsymSecureFileOutputStream outputStream = new AsymSecureFileOutputStream(OperationType.SIGN, bos, provider)) {
                outputStream.setAsymKey(keyPair);
                outputStream.setAuthKey("TEST".getBytes());
                outputStream.enableTimestamping(true, "http://tsa.starfieldtech.com");

                outputStream.setUserChunk(
                        UserChunk.builder()
                                .withUserCode((short) 0x0001)
                                .withData(new byte[]{0x10, 0x20, 0x30, 0x40, 0x50})
                                .build());
                outputStream.setUserChunk(
                        UserChunk.builder()
                                .encryptWithAuthKey()
                                .withUserCode((short) 0x0002)
                                .withData(new byte[]{0x10, 0x20, 0x30, 0x40, 0x50})
                                .build());

                for (int i = 0; i < 10000; i++) {
                    outputStream.write(10);
                }

                outputStream.finish();
            }

            try (OutputStream fos = new FileOutputStream("G:\\jasf4-test-output.bin")) {
                fos.write(bos.toByteArray());
            }

            byte[] payload = bos.toByteArray();
        }

        InputStream is = new FileInputStream(new File("G:\\jasf4-test-output.bin"));

        try(AsymSecureFileInputStream inputStream = new AsymSecureFileInputStream(is, provider))
        {
            while(inputStream.headerRead() == 1)
            {
                System.out.println("continous head reading");
            }

            inputStream.setAuthKey("TEST".getBytes());
            inputStream.setAsymKey(keyPair);

            Enumeration<UserChunk> enumeration = inputStream.userChunks();
            while (enumeration.hasMoreElements()) {
                UserChunk userChunk = enumeration.nextElement();
                System.out.println("userChunk : " + userChunk + " / " + userChunk.getDataSize() + " / " + bytesToHex(userChunk.getData()));
            }

            int readlen;
            byte[] buffer = new byte[8192];
            while((readlen = inputStream.read(buffer)) > 0) {
                System.out.println("READLEN : " + readlen + " // " + bytesToHex(Arrays.copyOf(buffer, readlen)));
            }
        }

        System.out.println("PublicKey : " + bytesToHex(keyPair.getPublic().getEncoded()));

        System.out.println("PrivateKey : " + bytesToHex(keyPair.getPrivate().getEncoded()));

//        System.out.println("PAYLOAD : " + bytesToHex(payload));
    }

    public void keyGen() throws Exception {


        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        KeyPair keyPairA = keyPairGenerator.generateKeyPair();
        KeyPair keyPairB = keyPairGenerator.generateKeyPair();

        System.out.println("A PUBLIC : " + bytesToHex(keyPairA.getPublic().getEncoded()));
        System.out.println("A PRIVATE : " + bytesToHex(keyPairA.getPrivate().getEncoded()));

        System.out.println("B PUBLIC : " + bytesToHex(keyPairB.getPublic().getEncoded()));
        System.out.println("B PRIVATE : " + bytesToHex(keyPairB.getPrivate().getEncoded()));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(keyPairA.getPrivate());
        Key key = keyAgreement.doPhase(keyPairB.getPublic(), true);
        //System.out.println("ENCODED : " + bytesToHex(key.getEncoded()));

        System.out.println("SECRET : " + bytesToHex(keyAgreement.generateSecret()));
    }

    KeyPair keyPair;
    void appMain() throws Exception {
        try(InputStream fis = new FileInputStream("G:\\jasf-test\\private.key")) {
            keyPair = parsePrivateKey(fis, null);
        }

        normalTest2();

        System.out.println(keyPair);
    }

    public static void main(String[] args) throws Exception {
        TestMain app = new TestMain();
        app.appMain();
    }
}
