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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SSLServer {
    public static void main(String[] args) throws KeyStoreException,
     FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        //Load the keystore
        char[] password = "password".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        FileInputStream keyStoreStream = new FileInputStream("keystore.p12");
        keyStore.load(keyStoreStream, password);

        // Create the SSLContext with the keystore
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // Set up the server socket factory
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(12345);
        System.out.println("Server started. Waiting for client connection...");

        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            // Read the client's message
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String message = reader.readLine();
            System.out.println("Received from client: " + message);

            // Send a response
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
            writer.println("Message received securely!");

            clientSocket.close();
        }

    }
}
