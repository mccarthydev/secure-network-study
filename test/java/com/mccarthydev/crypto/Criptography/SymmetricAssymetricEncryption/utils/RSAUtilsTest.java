package com.mccarthydev.crypto.Criptography.SymmetricAssymetricEncryption.utils;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RSAUtilsTest {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    public void setup() throws Exception{
        RSAUtils.storeKeysToFiles();
        privateKey = RSAUtils.getPrivateKey();
        publicKey = RSAUtils.getPublicKey();
    }
    
    @Test
    public void testSuccesfulEncryption() throws Exception {
        String input = "This is a test string";
        String cipherText = RSAUtils.encrypt("RSA", input, publicKey);
        String plainText = RSAUtils.decrypt("RSA", cipherText, privateKey);
        assert(input.equals(plainText));
    }
}
