package esb.framework.java.lib;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DecryptField {
    private static final String SECRET_KEY = "YourSecretKey123"; // Same 16-byte key used in encryption

    public static String decrypt(String encryptedInput) {
        try {
            SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedInput); // Decode from Base64
            byte[] decryptedBytes = cipher.doFinal(decodedBytes); // Perform AES decryption
            return new String(decryptedBytes); // Convert bytes to string
        } catch (Exception e) {
            e.printStackTrace();
            return ""; // Avoid null
        }
    }
}
