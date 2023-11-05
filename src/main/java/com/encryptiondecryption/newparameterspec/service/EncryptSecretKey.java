package com.encryptiondecryption.newparameterspec.service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class EncryptSecretKey {

    public static String encryptString(SecretKey key, String plainText) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(GenerateSecretKey.iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return GenerateSecretKey.bytesToHex(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException
                 | UnsupportedEncodingException | ShortBufferException
                 | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

}
