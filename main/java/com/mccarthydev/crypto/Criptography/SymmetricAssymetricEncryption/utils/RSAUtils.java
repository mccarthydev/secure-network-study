package com.mccarthydev.crypto.Criptography.SymmetricAssymetricEncryption.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAUtils {
    public static String encrypt(String algorithm, String input, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static void storeKeysToFiles() throws NoSuchAlgorithmException, FileNotFoundException, IOException{
        KeyPair keyPair = generateKeys();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        File publicKeyFile = new File("src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/asymmetric-keys/public-key.txt");
        File privateKeyFile = new File("src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/asymmetric-keys/private-key.txt");

        try(FileOutputStream publicKeyStream = new FileOutputStream(publicKeyFile);
            FileOutputStream privateKeyStream = new FileOutputStream(privateKeyFile)){
            publicKeyStream.write(publicKey.getEncoded());
            privateKeyStream.write(privateKey.getEncoded());
        }
    }

    private static KeyPair generateKeys() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File publicKeyFile = new File(
            "src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/asymmetric-keys/public-key.txt");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File privateKeyFile = new File(
            "src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/asymmetric-keys/private-key.txt");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

}
