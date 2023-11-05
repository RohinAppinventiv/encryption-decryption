package com.encryptiondecryption.ECCSpec.service;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;


public class SessionKeyGenerator {
    //Load bouncycastle
    public static SecretKey loadBouncyCastleProvider() throws NoSuchAlgorithmException, NoSuchProviderException {
            Security.addProvider(new BouncyCastleProvider());
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            SecretKey sessionKey =  keyGenerator.generateKey();
            System.out.println("Session Key  :  "+sessionKey.toString());
            return sessionKey;
    }
}
