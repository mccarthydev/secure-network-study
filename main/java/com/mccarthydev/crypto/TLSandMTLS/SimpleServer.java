package main.java.com.mccarthydev.crypto.TLSandMTLS;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SimpleServer {
    public static void main(String[] args) throws Exception{
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server is running and waiting for connections...");
        while(true){
            Socket clientSocket = serverSocket.accept();
            BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true);
            
            String clientMessage = input.readLine();
            System.out.println("Client message: "+ clientMessage);

            output.println("Server here");

            clientSocket.close();
            System.out.println("Client connection closed.");
        }
    }
}
