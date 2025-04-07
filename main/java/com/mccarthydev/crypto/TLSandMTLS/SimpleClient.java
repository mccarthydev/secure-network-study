package main.java.com.mccarthydev.crypto.TLSandMTLS;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
public class SimpleClient {
    public static void main(String[] args) throws Exception{
        Socket socket = new Socket("localhost", 12345);
        
        BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

        output.println("Hello server, I'm here :)");

        System.out.println(input.readLine());
    }
}
