package com.mccarthydev.crypto.CertificatesAndCAs;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class CertificateHandler {
        public static void main(String[] args) throws Exception {
        // Load a certificate from a file
        FileInputStream certFile = new FileInputStream("server.crt");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certFile);

        // Display the certificate info
        System.out.println("Certificate Subject: " + certificate.getSubjectDN());
        System.out.println("Certificate Issuer: " + certificate.getIssuerDN());
        System.out.println("Certificate Valid From: " + certificate.getNotBefore());
        System.out.println("Certificate Valid Until: " + certificate.getNotAfter());

        // Set up the TrustManager for certificate validation
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream trustStoreStream = new FileInputStream("truststore.p12")) {
            trustStore.load(trustStoreStream, "password".toCharArray());
        }
        tmf.init(trustStore);

        // Implement SSLContext with the TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
    }
}
