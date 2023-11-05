package com.encryptiondecryption.newparameterspec.service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class DecryptText {

    public static String decryptString(SecretKey key, String cipherText) {
        try {
            Key decryptionKey = new SecretKeySpec(key.getEncoded(),
                    key.getAlgorithm());
            IvParameterSpec ivSpec = new IvParameterSpec(GenerateSecretKey.iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] cipherTextBytes = GenerateSecretKey.hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0,
                    cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException
                 | IllegalBlockSizeException | BadPaddingException
                 | ShortBufferException | UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
