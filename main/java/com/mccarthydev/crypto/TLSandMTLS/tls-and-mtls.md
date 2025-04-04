# TLS and MTLS

## TLS (Transport Layer Security)

### What is TLS?

ref: https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/

Transport Layer Security, or TLS, is a widely adopted security protocol designed to facilitate privacy and data security for communications over the Internet. A primary use case of TLS is encrypting the communication between web applications and servers, such as web browsers loading a website.

**TLS vs SSL**

TLS evolved from a previous encryption protocol called Secure Sockets Layer (SSL), which was developed by Netscape. TLS version 1.0 actually began development as SSL version 3.1, but the name of the protocol was changed before publication in order to indicate that it was no longer associated with Netscape. Because of this history, the terms TLS and SSL are sometimes used interchangeably.

**TLS vs HTTP**

HTTP + TLS = HTTPS

**What does TLS do?**

There are three main components to what the TLS protocol accomplishes: Encryption, Authentication, and Integrity.

* **Encryption:** hides the data being transferred from third parties.
* **Authentication:** ensures that the parties exchanging information are who they claim to be.
* **Integrity:** verifies that the data has not been forged or tampered with.

### How does TLS work?

A TLS connection is initiated using a sequence known as the TLS handshake. When a user navigates to a website that uses TLS, the TLS handshake begins between the user's device (also known as the client device) and the web server.

During the TLS handshake, the user's device and the web server:

* Specify which version of TLS (TLS 1.0, 1.2, 1.3, etc.) they will use
* Decide on which cipher suites they will use
* Authenticate the identity of the server using the server's TLS certificate
* Generate session keys for encrypting messages between them after the handshake is complete

### Execise

https://www.baeldung.com/java-ssl

**Extra:** 

* Factory design pattern: https://www.baeldung.com/java-factory-pattern

### Chat GPT Proposed Project

**Prompt:**

```
Can you present to me a very simple and crude project for me to understand SSL in java using technologies such as SSLContext, SSLSocketFactory etc. I would like to create a local client and server and send secure messages between them. Later when I learn how to do this, I would like to have my local client sending secure messages to my hosting provider
```

**Result:**

Sure! I'll walk you through a simple Java project that uses SSL to securely exchange messages between a local client and server. You'll learn how to set up `SSLContext`, `SSLSocketFactory`, and how to use them to establish a secure connection.

### Overview of the Steps:
1. **Create a self-signed SSL certificate** (since this is a local project).
2. **Create the server** that accepts secure connections.
3. **Create the client** that connects securely to the server.
4. **Send a message from the client to the server** over the secure SSL connection.

### Step 1: Generate a Self-Signed SSL Certificate
To create a secure SSL connection, you need an SSL certificate. You can create a self-signed certificate for testing purposes. Run the following command in your terminal to generate a self-signed certificate and a keystore.

```sh
keytool -genkeypair -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650 -alias mykey
```

This will create a `keystore.p12` file, which you will later use in both your client and server code to establish an SSL connection.

### Step 2: SSL Server Code (Server.java)
The server will listen on a port and accept SSL connections. When the client connects securely, the server will read and respond with a message.

```java
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class SSLServer {

    public static void main(String[] args) throws Exception {
        // Load the keystore
        char[] password = "password".toCharArray(); // Password for the keystore
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
```

### Step 3: SSL Client Code (Client.java)
The client will establish a secure connection with the server and send a message.

```java
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class SSLClient {

    public static void main(String[] args) throws Exception {
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
```

### Step 4: Running the Server and Client
1. **Start the server** first. It will wait for incoming client connections.
   ```bash
   javac SSLServer.java
   java SSLServer
   ```

2. **Run the client**. It will connect to the server and send a message.
   ```bash
   javac SSLClient.java
   java SSLClient
   ```

### Expected Output:
**Server:**
```bash
Server started. Waiting for client connection...
Client connected: /127.0.0.1
Received from client: Hello, server! This is a secure message.
```

**Client:**
```bash
Connected to server
Received from server: Message received securely!
```

### Step 5: Sending Secure Messages to a Hosting Provider
When you move to a live hosting provider, you won't need a self-signed certificate. You can get a certificate from a trusted Certificate Authority (CA). The general flow for connecting to a remote server will be:

- Replace `"localhost"` in the client with your hosting provider's domain.
- Use the appropriate certificate for the server and update the truststore accordingly.

This is the basic idea behind SSL communication using Java. Once you understand this setup, you can securely exchange messages with remote servers in a production environment.