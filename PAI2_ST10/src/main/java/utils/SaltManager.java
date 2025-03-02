package utils;
import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SaltManager {
    private static final String ENCRYPTION_KEY = "ThisIsASecretKey";
    private static final String SALT_FILE = "salts.enc";

    // Guarda una salt cifrada en el archivo
    public static void saveSalt(String username, String salt) {
        try (FileWriter writer = new FileWriter(SALT_FILE, true)) {
            String encryptedSalt = encrypt(salt);
            writer.write(username + ":" + encryptedSalt + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Obtiene una salt descifrada desde el archivo
    public static String getSalt(String username) {
        try (BufferedReader reader = new BufferedReader(new FileReader(SALT_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts[0].equals(username)) {
                    return decrypt(parts[1]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Cifra un texto usando AES
    private static String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Descifra un texto usando AES
    private static String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

