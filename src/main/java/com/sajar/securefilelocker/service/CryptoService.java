package com.sajar.securefilelocker.service;

import com.sajar.securefilelocker.exception.ApiExceptions;
import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * File encryption core.
 *
 * Layout of an encrypted file on disk:  [ salt (16 bytes) | iv (12 bytes) | AES-GCM ciphertext+tag ]
 *
 * The user's file password is never persisted anywhere. To "verify" a password on
 * download, we simply attempt the decryption: AES-GCM's authentication tag fails
 * to verify if the derived key is wrong, which throws AEADBadTagException. That
 * failure IS the password check - there's no separate stored hash to compare against.
 */
@Service
public class CryptoService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AES_KEY_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private byte[] deriveKey(char[] password, byte[] salt) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new ApiExceptions.FileAccessException("Key derivation failed: " + e.getMessage());
        }
    }

    /**
     * Encrypts inputStream into outputStream, writing salt+iv followed by ciphertext.
     * Caller is responsible for closing both streams.
     */
    public void encrypt(InputStream inputStream, OutputStream outputStream, String password) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_BYTES];
            RANDOM.nextBytes(iv);

            SecretKey key = new SecretKeySpec(deriveKey(password.toCharArray(), salt), "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

            outputStream.write(salt);
            outputStream.write(iv);

            try (CipherOutputStream cos = new CipherOutputStream(outputStream, cipher)) {
                inputStream.transferTo(cos);
            }
        } catch (IOException e) {
            throw new ApiExceptions.FileAccessException("Encryption I/O error: " + e.getMessage());
        } catch (Exception e) {
            throw new ApiExceptions.FileAccessException("Encryption failed: " + e.getMessage());
        }
    }

    /**
     * Decrypts encryptedInput (salt+iv+ciphertext) into outputStream using the given password.
     * Throws WrongFilePasswordException if the password is wrong or the file is corrupted/tampered with.
     */
    public void decrypt(InputStream encryptedInput, OutputStream outputStream, String password) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            if (encryptedInput.readNBytes(salt, 0, SALT_BYTES) != SALT_BYTES) {
                throw new ApiExceptions.FileAccessException("Encrypted file is truncated (missing salt)");
            }
            byte[] iv = new byte[GCM_IV_BYTES];
            if (encryptedInput.readNBytes(iv, 0, GCM_IV_BYTES) != GCM_IV_BYTES) {
                throw new ApiExceptions.FileAccessException("Encrypted file is truncated (missing IV)");
            }

            SecretKey key = new SecretKeySpec(deriveKey(password.toCharArray(), salt), "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

            try (CipherInputStream cis = new CipherInputStream(encryptedInput, cipher)) {
                cis.transferTo(outputStream);
            }
        } catch (IOException e) {
            if (isAuthTagFailure(e)) {
                throw new ApiExceptions.WrongFilePasswordException();
            }
            throw new ApiExceptions.FileAccessException("Decryption I/O error: " + e.getMessage());
        } catch (ApiExceptions.FileAccessException | ApiExceptions.WrongFilePasswordException e) {
            throw e;
        } catch (Exception e) {
            if (isAuthTagFailure(e)) {
                throw new ApiExceptions.WrongFilePasswordException();
            }
            throw new ApiExceptions.FileAccessException("Decryption failed: " + e.getMessage());
        }
    }

    private boolean isAuthTagFailure(Throwable t) {
        Throwable current = t;
        while (current != null) {
            if (current instanceof AEADBadTagException) {
                return true;
            }
            if (current.getMessage() != null &&
                    (current.getMessage().contains("Tag mismatch") || current.getMessage().contains("AEADBadTagException"))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
