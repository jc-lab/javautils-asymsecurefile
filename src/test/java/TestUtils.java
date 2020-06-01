import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class TestUtils {
    private static final Map<ASN1ObjectIdentifier, String> ALGORITHMS = new HashMap();
    private static final Provider SECURITY_PROVIDER = new BouncyCastleProvider();

    static
    {
        ALGORITHMS.put(X9ObjectIdentifiers.id_ecPublicKey, "EC");
        ALGORITHMS.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        ALGORITHMS.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    public static String trimAllLines(String input) {
        StringBuilder stringBuilder = new StringBuilder();
        String[] lines = input.split("\n");
        for(String line : lines) {
            stringBuilder.append(line.trim());
            stringBuilder.append("\n");
        }
        return stringBuilder.toString();
    }

    public static PrivateKey parsePrivateKeyPem(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(trimAllLines(pem).getBytes())));
        Object pemObject = pemParser.readObject();
        PrivateKeyInfo privateKeyInfo = null;
        String algName;
        KeyFactory keyFactory;
        if(pemObject instanceof PrivateKeyInfo) {
            privateKeyInfo = (PrivateKeyInfo)pemObject;
        }else if(pemObject instanceof PEMKeyPair){
            PEMKeyPair pemKeyPair = (PEMKeyPair)pemObject;
            privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
        }
        assert privateKeyInfo != null;
        algName = ALGORITHMS.get(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
        if(algName == null)
            algName = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
        keyFactory = KeyFactory.getInstance(algName, SECURITY_PROVIDER);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
    }

    public static PublicKey parsePublicKeyPem(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(trimAllLines(pem).getBytes())));
        Object pemObject = pemParser.readObject();
        SubjectPublicKeyInfo publicKeyInfo = null;
        String algName;
        KeyFactory keyFactory;
        if(pemObject instanceof SubjectPublicKeyInfo) {
            publicKeyInfo = (SubjectPublicKeyInfo)pemObject;
        }
        assert publicKeyInfo != null;
        algName = ALGORITHMS.get(publicKeyInfo.getAlgorithm().getAlgorithm());
        if(algName == null)
            algName = publicKeyInfo.getAlgorithm().getAlgorithm().getId();
        keyFactory = KeyFactory.getInstance(algName, SECURITY_PROVIDER);
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded("X509")));
    }

    public static String dump(byte[] data) {
        return dump(data, false);
    }

    public static String dump(byte[] data, boolean showOffset) {
        StringBuilder output = new StringBuilder();
        for (int i=0; i<data.length; i++) {
            if (showOffset && ((i % 16) == 0)) {
                if (output.length() > 0) {
                    output.append("\n");
                }
                output.append(String.format("%08d", i));
                output.append(": ");
            }

            output.append(String.format("%02x", data[i] & 0xFF));
            output.append(" ");
        }
        return output.toString();
    }
}
