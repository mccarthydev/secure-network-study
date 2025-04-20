package com.mccarthydev.crypto.CertificatesAndCAs;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CertificateValidation {
        public static void main(String[] args) throws Exception {
        // Load the certificate into a certificate chain
        FileInputStream certFile = new FileInputStream("server.crt");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certFile);

        // Load the truststore and initialize the TrustManager
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream trustStoreStream = new FileInputStream("truststore.p12")) {
            trustStore.load(trustStoreStream, "password".toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create the SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());

        // Validate the certificate against the truststore
        X509TrustManager x509TrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        try {
            x509TrustManager.checkServerTrusted(new X509Certificate[]{certificate}, "RSA");
            System.out.println("Certificate is trusted.");
        } catch (CertificateException e) {
            System.out.println("Certificate is not trusted: " + e.getMessage());
        }
    }
}
