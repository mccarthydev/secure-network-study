package com.mccarthydev.crypto.Criptography.SymmetricAssymetricEncryption.utils;

import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AESUtilsTest {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private SecretKey key;
    private IvParameterSpec iv = AESUtils.generateIV();

    @BeforeEach
    public void setup() throws Exception {
       key = AESUtils.generateKey(128);
    }

    @Test
    public void testSuccessfulStringEncryption() throws Exception {
        String input = "This is a test";
        String cipherText = AESUtils.encrypt(ALGORITHM, input, key, iv);
        String decryptedCipherText  = AESUtils.decrypt(ALGORITHM, cipherText, key, iv);
        assertEquals(input, decryptedCipherText);
    }

    @Test
    public void testSuccessfulFileEncryption() throws Exception {        
        File inputFile = new File("src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/input.txt");
        File encryptedFile = new File("src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/encryptedInput.txt");
        File decryptedFile = new File("src/main/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/files/decryptedInput.txt");

        AESUtils.encryptFile(inputFile, encryptedFile, ALGORITHM, key, iv);
        AESUtils.decryptFile(encryptedFile, decryptedFile, ALGORITHM, key, iv);
    }

}
