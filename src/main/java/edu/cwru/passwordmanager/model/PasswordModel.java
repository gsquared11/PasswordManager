package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    private static String verifyString = "cookies";

    private void loadPasswords() {
        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            // Skip the first line (Salt + Token)
            String headerLine = reader.readLine();

            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    String[] parts = line.split(separator);
                    if (parts.length < 2) continue;

                    String label = parts[0];
                    String encryptedPwd = parts[1];

                    String decryptedPwd = decryptPassword(encryptedPwd);
                    getPasswords().add(new Password(label, decryptedPwd));
                } catch (Exception e) {
                    System.err.println("Skipping corrupted password entry: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading password file: " + e.getMessage());
        }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();
        passwordFilePassword = password;
        try {
            generateSalt();
            generateKey();
            new PasswordModel().saveAllPasswords();
        } catch (Exception e) {
            throw new IOException("Failed to initialize security keys", e);
        }
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE

        if (!passwordFileExists()) return false;

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            String line = reader.readLine();
            String[] parts = line.split(separator);

            passwordFileSalt = Base64.getDecoder().decode(parts[0]);
            generateKey();
            String decryptedVerify = decryptPassword(parts[1]);

            return verifyString.equals(decryptedVerify);
        } catch (Exception e) {
            return false;
        }
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        if (index >= 0 && index < getPasswords().size()) {
            getPasswords().remove(index);
            saveAllPasswords();
        }
    }

    public void updatePassword(Password password, int index) {
        if (index >= 0 && index < getPasswords().size()) {
            getPasswords().set(index, password);
            saveAllPasswords();
        }
    }

    public void addPassword(Password password) {
        getPasswords().add(password);
        saveAllPasswords();
    }

    private void saveAllPasswords() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(passwordFile))) {
            String encryptedVerify = encryptPassword(verifyString);
            writer.println(Base64.getEncoder().encodeToString(passwordFileSalt) + separator + encryptedVerify);

            for (Password p : getPasswords()) {
                writer.println(p.getLabel() + separator + encryptPassword(p.getPassword()));
            }
        } catch (Exception e) {
            System.err.println("Error saving passwords: " + e.getMessage());
        }
    }

    private static void generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        passwordFileSalt = new byte[16];
        secureRandom.nextBytes(passwordFileSalt);
    }


    private static void generateKey() {
        try {
            KeySpec spec = new PBEKeySpec(passwordFilePassword.toCharArray(), passwordFileSalt, 600000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey privateKey = factory.generateSecret(spec);
            passwordFileKey = privateKey.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate secret key", e);
        }
    }

    private static String encryptPassword(String text) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(passwordFileKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(text.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt password", e);
        }
    }

    private static String decryptPassword(String encryptedText) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(passwordFileKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decoded = Base64.getDecoder().decode(encryptedText);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt password", e);
        }
    }
}
