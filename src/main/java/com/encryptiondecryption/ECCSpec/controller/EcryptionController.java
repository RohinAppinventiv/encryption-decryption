package com.encryptiondecryption.ECCSpec.controller;

import com.encryptiondecryption.ECCSpec.service.SessionKeyEncryption;
import com.encryptiondecryption.ECCSpec.service.SessionKeyGenerator;
import com.encryptiondecryption.ECCSpec.service.DataEncryption;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;

@RestController
@RequestMapping("/api/*")
public class EcryptionController {

    @GetMapping("/encryptdata")
    public ResponseEntity<?> getEcryptedData() throws Exception {
        SecretKey secretKey = SessionKeyGenerator.loadBouncyCastleProvider();
        String data = "this is my life";
        System.out.println("Normal Text : "+data);
        System.out.println("Secret Key or Session Key : "+secretKey);
        String encryptedDataWithSessionKey = DataEncryption.encryptString(data, secretKey);
        System.out.println("Ecrypted Data With Session Key : "+encryptedDataWithSessionKey);
        String eccKey = SessionKeyEncryption.generateECCKey(secretKey);
        System.out.println("Ecrypted Session Key with ECC : "+eccKey);


        return ResponseEntity.ok().body(null);
    }





}
