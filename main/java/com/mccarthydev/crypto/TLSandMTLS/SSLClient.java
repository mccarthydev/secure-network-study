package com.mccarthydev.crypto.TLSandMTLS;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SSLClient {
    public static void main(String[] args) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException {
                // Load the truststore (we are trusting the server's certificate)
        char[] password = "password".toCharArray(); // Password for the truststore
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        FileInputStream trustStoreStream = new FileInputStream("keystore.p12");
        trustStore.load(trustStoreStream, password);

        // Create the SSLContext with the truststore
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        // Set up the socket factory
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 12345);
        System.out.println("Connected to server");

        // Send a message to the server
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
        writer.println("Hello, server! This is a secure message.");

        // Read the response from the server
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String response = reader.readLine();
        System.out.println("Received from server: " + response);

        socket.close();
    }
}
