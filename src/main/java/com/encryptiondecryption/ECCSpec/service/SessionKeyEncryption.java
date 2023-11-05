package com.encryptiondecryption.ECCSpec.service;


import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.field.FiniteField;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Enumeration;

public class SessionKeyEncryption {



    public static String encryptionSessionKey(SecretKey sessionKey, PublicKey eccPublicKey) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        byte[] encryptedSessionKey = cipher.doFinal(sessionKey.getEncoded());
        String encryptedKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
        return encryptedKey;
    }
    public static String generateECCKey(SecretKey sessionKey) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecParameterSpec(), new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey eccPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey eccPrivateKey = (ECPrivateKey)keyPair.getPrivate();
        String ecryptedSessionKey= encryptionSessionKey(sessionKey, eccPublicKey);
        System.out.println("Encrypted Session key: "+ecryptedSessionKey);

        return ecryptedSessionKey;
    }
    public static ECParameterSpec ecParameterSpec(){
//       X9ECParameters curveParams = ECNamedCurveTable.getByName("secp256r1");
//        ECNamedCurveParameterSpec curveSpec = new ECNamedCurveParameterSpec(
//                "secp256r1",
//                curveParams.getCurve(),
//                curveParams.getG(),
//                curveParams.getN(),
//                curveParams.getH(),
//                curveParams.getSeed()
//        );
//        ECParameterSpec ecSpec = new ECParameterSpec(curveSpec);
//        EllipticCurve curve = new EllipticCurve(
//                new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
//                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
//                new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
//        );
//
//// Define the correct generator point for SecP256R1
//        ECPoint generator = new ECPoint(
//                new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
//                new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7E0D67A52514A02B5D4FF1780CDE57B6BA0A7E36E163B31A797416783ACC1D7D9C998CEA607B0CF029", 16)
//        );
//
//// Define the order and cofactor
//        BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
//        int cofactor = 1;
//        ECParameterSpec ecSpec = new ECParameterSpec(curve, generator, order, cofactor);
//        return ecSpec;
        ECNamedCurveParameterSpec namedCurveParams = ECNamedCurveTable.getParameterSpec("secp256r1");
        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        );
        BigInteger xCoordinate = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
        BigInteger yCoordinate = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7E0D67A52514A02B5D4FF1780CDE57B6BA0A7E36E163B31A797416783ACC1D7D9C998CEA607B0CF029", 16);

        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        ECPoint ecPoint = new ECPoint(a,b);
       BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        ECParameterSpec parameterSpec = new ECParameterSpec(curve, ecPoint, order, 1);
        return parameterSpec;


    }
}
