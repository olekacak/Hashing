package com.secure;

import org.json.JSONObject;
import org.json.JSONArray;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class SecureHasher {
    static {
        System.loadLibrary("SecureHasherNative"); // Ensure this matches your compiled native library
    }

    public native String hashAndEncrypt(String input, String publicKey);

    public static void main(String[] args) {
        SecureHasher secureHasher = new SecureHasher();
        String input = "OleKacak";

        try {
            String jwkResponse = downloadPublicKey();
            System.out.println("JWK Response: " + jwkResponse);
            
            String pemPublicKey = extractPublicKeyFromJWK(jwkResponse);
            System.out.println("Extracted PEM Public Key:\n" + pemPublicKey);

            String encryptedHash = secureHasher.hashAndEncrypt(input, pemPublicKey);
            System.out.println("Encrypted Hash: " + encryptedHash);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String downloadPublicKey() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://demo.api.piperks.com/.well-known/pi-xcels.json"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public static String extractPublicKeyFromJWK(String jwkJson) throws Exception {
        JSONObject json = new JSONObject(jwkJson);
        JSONArray keys = json.getJSONArray("keys");
        JSONObject key = keys.getJSONObject(0);

        String n = key.getString("n");  // Modulus
        String e = key.getString("e");  // Exponent

        return convertJwkToPem(n, e);
    }
    

        public static String convertJwkToPem(String n, String e) throws Exception {
            byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
            byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                new java.math.BigInteger(1, modulusBytes),
                new java.math.BigInteger(1, exponentBytes)
            );
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return convertToPemFormat(publicKey);
        }

        private static String convertToPemFormat(PublicKey publicKey) throws Exception {
            String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            return "-----BEGIN PUBLIC KEY-----\n" + base64PublicKey + "\n-----END PUBLIC KEY-----";
        }

}
