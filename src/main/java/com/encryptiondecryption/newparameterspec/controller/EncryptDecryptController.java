package com.encryptiondecryption.newparameterspec.controller;

import com.encryptiondecryption.newparameterspec.service.DecryptText;
import com.encryptiondecryption.newparameterspec.service.EncryptSecretKey;
import com.encryptiondecryption.newparameterspec.service.GenerateECKeys;
import com.encryptiondecryption.newparameterspec.service.GenerateSecretKey;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

@RestController
public class EncryptDecryptController {

    @GetMapping("/data")
    public String getDecryptedString() throws NoSuchAlgorithmException {

        String plainText = "Hi Rohin, How You Doing!";
        System.out.println("Original plaintext message: " + plainText);

        // Initialize two key pairs
        KeyPair keyPairA = GenerateECKeys.generateECKeys();
        KeyPair keyPairB = GenerateECKeys.generateECKeys();

        // Create two AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA = GenerateSecretKey.generateSharedSecret(keyPairA.getPrivate(),
                keyPairB.getPublic());
        SecretKey secretKeyB = GenerateSecretKey.generateSharedSecret(keyPairB.getPrivate(),
                keyPairA.getPublic());

        // Encrypt the message using 'secretKeyA'
        String cipherText = EncryptSecretKey.encryptString(secretKeyA, plainText);
        System.out.println("Encrypted cipher text: " + cipherText);

        // Decrypt the message using 'secretKeyB'
        String decryptedPlainText = DecryptText.decryptString(secretKeyB, cipherText);
        System.out.println("Decrypted cipher text: " + decryptedPlainText);
        return null;
    }

}
