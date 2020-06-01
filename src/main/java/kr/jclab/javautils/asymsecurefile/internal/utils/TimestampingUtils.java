package kr.jclab.javautils.asymsecurefile.internal.utils;

import kr.jclab.javautils.asymsecurefile.TimestampRequestException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class TimestampingUtils {
    public static TimeStampToken sign(SecureRandom random, ASN1ObjectIdentifier digestAlgorithm, byte[] digest, String tsaLocation, int timeout) throws TimestampRequestException {
        try {
            TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
            requestGen.setCertReq(true);
            TimeStampRequest request = requestGen.generate(
                    digestAlgorithm,
                    digest,
                    BigInteger.valueOf(random.nextLong())
            );
            HttpPost postMethod = new HttpPost(tsaLocation);
            HttpEntity requestEntity = new ByteArrayEntity(request.getEncoded(), ContentType.create("application/timestamp-query"));
            postMethod.addHeader("User-Agent", "asymsecurefile client");
            postMethod.setEntity(requestEntity);
            RequestConfig.Builder requestConfigBuilder = RequestConfig.custom();
            requestConfigBuilder.setConnectTimeout(timeout);
            requestConfigBuilder.setConnectionRequestTimeout(timeout);
            HttpClient httpClient = HttpClientBuilder.create()
                    .setDefaultRequestConfig(requestConfigBuilder.build())
                    .build();
            HttpResponse httpResponse = httpClient.execute(postMethod);
            StatusLine statusLine = httpResponse.getStatusLine();
            int statusCode = statusLine.getStatusCode();
            if (statusCode != 200) {
                throw new TimestampRequestException("status_code=" + statusCode);
            }
            HttpEntity httpEntity = httpResponse.getEntity();
            TimeStampResponse tspResponse = new TimeStampResponse(
                    httpEntity.getContent());
            postMethod.releaseConnection();
            return tspResponse.getTimeStampToken();
        } catch (TSPException | IOException e) {
            throw new TimestampRequestException(e);
        }
    }
}
