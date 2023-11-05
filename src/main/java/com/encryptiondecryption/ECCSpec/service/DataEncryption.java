package com.encryptiondecryption.ECCSpec.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

public class DataEncryption {

    public static String encryptString(String data, SecretKey sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encryptBytes = cipher.doFinal(data.getBytes("UTF-8"));
        String encryptedData = Base64.getEncoder().encodeToString(encryptBytes);
        return encryptedData;
    }
}
