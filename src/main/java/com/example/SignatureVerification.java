package com.example;

import java.io.DataOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class SignatureVerification {

    public static void main(String[] args) throws Exception {
        // Carica il KeyStore "Windows-MY"
        KeyStore keyStore = KeyStore.getInstance("Windows-MY");
        keyStore.load(null, null);  // carica il keystore con il default parameter
        
        // Ottiene un alias dal keystore
        Enumeration<String> en = keyStore.aliases();
        while (en.hasMoreElements()) {
            String alias = en.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                // Ottiene il certificato e la chiave privata
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                PublicKey publicKey = certificate.getPublicKey();
                
                // Prepara i dati da firmare
                String data = "Monika";
                byte[] content = data.getBytes();
                
                // Crea una firma digitale
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(content);
                byte[] signatureBytes = signature.sign();
                
                // Verifica la firma
                Signature signatureVerifier = Signature.getInstance("SHA256withRSA");
                signatureVerifier.initVerify(publicKey);
                signatureVerifier.update(content);
                boolean verifies = signatureVerifier.verify(signatureBytes);
                
                System.out.println("Alias: " + alias);
                System.out.println("Signature verifies: " + verifies);
            }
        }
    }
}
