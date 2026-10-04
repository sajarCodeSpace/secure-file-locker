package com.sajar.securefilelocker.service;

import com.sajar.securefilelocker.dto.FileResponse;
import com.sajar.securefilelocker.exception.ApiExceptions;
import com.sajar.securefilelocker.model.StoredFile;
import com.sajar.securefilelocker.repository.StoredFileRepository;
import com.sajar.securefilelocker.util.FileUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
public class FileVaultService {

    private final StoredFileRepository storedFileRepository;
    private final StorageService storageService;
    private final CryptoService cryptoService;

    public FileVaultService(StoredFileRepository storedFileRepository,
                            StorageService storageService,
                            CryptoService cryptoService) {
        this.storedFileRepository = storedFileRepository;
        this.storageService = storageService;
        this.cryptoService = cryptoService;
    }

    @Transactional
    public FileResponse upload(Long userId, MultipartFile file, String password) {
        if (file.isEmpty()) {
            throw new ApiExceptions.FileAccessException("Uploaded file is empty");
        }

        String safeOriginalName = FileUtils.sanitizeFilename(file.getOriginalFilename());
        String storedFilename = UUID.randomUUID() + ".enc";

        try (InputStream in = file.getInputStream();
             ByteArrayOutputStream encryptedBuffer = new ByteArrayOutputStream()) {

            cryptoService.encrypt(in, encryptedBuffer, password);
            storageService.store(storedFilename, new ByteArrayInputStream(encryptedBuffer.toByteArray()));

        } catch (IOException e) {
            log.error("Failed to process file upload for user: {}", userId, e);
            throw new ApiExceptions.FileAccessException("Could not write encrypted file: " + e.getMessage());
        }

        StoredFile stored = StoredFile.builder()
                .userId(userId)
                .originalFilename(safeOriginalName)
                .storedFilename(storedFilename)
                .sizeBytes(file.getSize())
                .uploadedAt(LocalDateTime.now())
                .build();

        StoredFile saved = storedFileRepository.save(stored);
        log.info("AUDIT: File uploaded successfully [userId={}, fileId={}, originalName={}]",
                userId, saved.getId(), safeOriginalName);

        return toResponse(saved);
    }

    public List<FileResponse> listFiles(Long userId) {
        return storedFileRepository.findByUserId(userId).stream()
                .map(this::toResponse)
                .toList();
    }

    /**
     * Decrypts and returns the file bytes.
     * Throws WrongFilePasswordException if the password is wrong or the file is tampered with.
     */
    public DecryptedFile download(Long userId, Long fileId, String password) {
        StoredFile stored = storedFileRepository.findByIdAndUserId(fileId, userId)
                .orElseThrow(() -> new ApiExceptions.ResourceNotFoundException("File not found or access denied"));

        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();

        try (InputStream encryptedIn = storageService.load(stored.getStoredFilename())) {
            cryptoService.decrypt(encryptedIn, decryptedOut, password);
        } catch (IOException e) {
            log.error("Storage read error during download [userId={}, fileId={}]", userId, fileId, e);
            throw new ApiExceptions.FileAccessException("Could not read encrypted file: " + e.getMessage());
        }

        log.info("AUDIT: File decrypted and downloaded [userId={}, fileId={}]", userId, fileId);
        return new DecryptedFile(stored.getOriginalFilename(), decryptedOut.toByteArray());
    }

    @Transactional
    public void delete(Long userId, Long fileId) {
        StoredFile stored = storedFileRepository.findByIdAndUserId(fileId, userId)
                .orElseThrow(() -> new ApiExceptions.ResourceNotFoundException("File not found or access denied"));

        storageService.delete(stored.getStoredFilename());
        storedFileRepository.delete(stored);

        log.info("AUDIT: File deleted [userId={}, fileId={}]", userId, fileId);
    }

    private FileResponse toResponse(StoredFile f) {
        return new FileResponse(f.getId(), f.getOriginalFilename(), f.getSizeBytes(), f.getUploadedAt());
    }

    public record DecryptedFile(String originalFilename, byte[] content) {}
}
