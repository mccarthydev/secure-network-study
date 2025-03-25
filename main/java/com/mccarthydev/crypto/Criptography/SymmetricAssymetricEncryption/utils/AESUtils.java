package com.mccarthydev.crypto.Criptography.SymmetricAssymetricEncryption.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESUtils {

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static void encryptFile(File inputFile, File outputFile, String algorithm, SecretKey key, IvParameterSpec iv) throws IOException, NoSuchAlgorithmException,
        NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        byte[] buffer = new byte[16];

        int bytesRead;
        while((bytesRead = inputStream.read(buffer)) != -1){
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if(output != null){
                outputStream.write(output);
            }
        }

        byte[] finalBlock = cipher.doFinal();
        if(finalBlock != null) {
            outputStream.write(finalBlock);
        }

        inputStream.close();
        outputStream.close();
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException,
     NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static void decryptFile(File inputFile, File outputFile, String algorithm, SecretKey key, IvParameterSpec iv) throws IOException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        byte[] buffer = new byte[16];

        int bytesRead;
        while((bytesRead = inputStream.read(buffer)) != -1){
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if(output != null){
                outputStream.write(output);
            }
        }

        byte[] finalBlock = cipher.doFinal();
        if(finalBlock != null) {
            outputStream.write(finalBlock);
        }

        inputStream.close();
        outputStream.close();
}

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
