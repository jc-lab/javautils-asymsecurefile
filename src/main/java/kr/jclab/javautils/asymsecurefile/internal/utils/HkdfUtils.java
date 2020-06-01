package kr.jclab.javautils.asymsecurefile.internal.utils;

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.security.MessageDigest;

public class HkdfUtils {
    @FunctionalInterface
    public interface DigestFactory {
        MessageDigest create();
    }

    public static byte[] generateKey(
            HashAlgorithms.AlgorithmEntry algorithmEntry,
            final byte[] master,
            int length,
            final byte[] salt) {
        HKDFParameters parameters = new HKDFParameters(
                master, salt, null
        );
        HKDFBytesGenerator generator = new HKDFBytesGenerator(algorithmEntry.getBcDigestSupplier().get());
        byte[] output = new byte[length];
        generator.init(parameters);
        generator.generateBytes(output, 0, output.length);
        return output;
    }

}
