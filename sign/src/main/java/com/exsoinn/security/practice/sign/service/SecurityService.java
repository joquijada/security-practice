package com.exsoinn.security.practice.sign.service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class SecurityService {
    @Autowired
    ResourceLoader resourceLoader;

    private static final String KEY_STORE_PASSWORD = "t@klJ7nc8zyCHI";

    public String requestToken() throws GeneralSecurityException, IOException {
        String requestId = UUID.randomUUID().toString();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(loadKeyStore(), KEY_STORE_PASSWORD.toCharArray());
        Enumeration<String> es = keyStore.aliases();
        String alias = es.nextElement();

        // Get private key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, KEY_STORE_PASSWORD.toCharArray());

        // Get certificate
        Certificate[] chain = keyStore.getCertificateChain(alias);
        Certificate certificate = chain[0];
        String publicCertificate;
        try {
            publicCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        String timestamp = format.format(now);
        String textToSign = String.format("%s|%s|%s", requestId, timestamp, publicCertificate);

        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        signature.update(textToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signatureData = signature.sign();
        String signatureDataBase64 = Base64.getEncoder().encodeToString(signatureData);
        JSONObject obj = new JSONObject();
        obj.put("RequestGUID", requestId);
        obj.put("Timestamp", timestamp);
        obj.put("PublicCertificate", publicCertificate);
        obj.put("Signature", signatureDataBase64);

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(
                        "https://mas2-hiscloudsts.soa-di.aws.3mhis.net")
                .path("/CoreSTS/token/issue/certificate");

        String response = getWebClient()
                .post()
                .uri(uriBuilder.toUriString())
                .contentType(MediaType.APPLICATION_JSON)
                .body(Mono.just(obj.toString()), String.class)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        assert response != null;
        return Base64.getEncoder().encodeToString(response.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream loadKeyStore() throws IOException {
        return resourceLoader
                .getResource("classpath:com/exsoinn/security/practice/sign/key-store.jks")
                .getInputStream();
    }

    private WebClient getWebClient() {
        return WebClient.builder()
                .defaultHeader(HttpHeaders.CONNECTION, "close")
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(128 * 1024 * 1024))
                        .build())
                .build();
    }
}
