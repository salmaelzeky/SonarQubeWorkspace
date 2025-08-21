package esb.framework.java.lib;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EncryptField {
    private static final String SECRET_KEY = "YourSecretKey123"; // 16-byte key

    public static String encrypt(String input) {
        try {
            System.out.println("Encrypt method called with: " + input);
            
            SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // More explicit
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encryptedBytes = cipher.doFinal(input.getBytes("UTF-8"));
            String result = Base64.getEncoder().encodeToString(encryptedBytes);

            System.out.println("Encrypted result: " + result);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return "ERROR: " + e.getMessage(); // Help you debug from ESQL
        }
    }
}
