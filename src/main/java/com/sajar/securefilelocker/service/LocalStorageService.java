package com.sajar.securefilelocker.service;

import com.sajar.securefilelocker.exception.ApiExceptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@Service
@Slf4j
public class LocalStorageService implements StorageService {

    private final Path lockerDir;

    public LocalStorageService(@Value("${app.storage.locker-dir:locked_files}") String lockerDirPath) {
        this.lockerDir = Path.of(lockerDirPath).toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.lockerDir);
            log.info("Initialized local file storage at: {}", this.lockerDir);
        } catch (IOException e) {
            throw new ApiExceptions.FileAccessException("Could not create locker directory: " + e.getMessage());
        }
    }

    private Path resolveSafePath(String filename) {
        Path resolved = lockerDir.resolve(filename).normalize();
        if (!resolved.startsWith(lockerDir)) {
            throw new ApiExceptions.FileAccessException("Invalid storage path traversal attempt");
        }
        return resolved;
    }

    @Override
    public void store(String storedFilename, InputStream inputStream) {
        Path target = resolveSafePath(storedFilename);
        try {
            Files.copy(inputStream, target, StandardCopyOption.REPLACE_EXISTING);
            log.debug("Stored blob: {}", storedFilename);
        } catch (IOException e) {
            throw new ApiExceptions.FileAccessException("Failed to store file: " + e.getMessage());
        }
    }

    @Override
    public InputStream load(String storedFilename) {
        Path target = resolveSafePath(storedFilename);
        if (!Files.exists(target)) {
            throw new ApiExceptions.ResourceNotFoundException("File not found on storage");
        }
        try {
            return Files.newInputStream(target);
        } catch (IOException e) {
            throw new ApiExceptions.FileAccessException("Failed to read stored file: " + e.getMessage());
        }
    }

    @Override
    public void delete(String storedFilename) {
        Path target = resolveSafePath(storedFilename);
        try {
            boolean deleted = Files.deleteIfExists(target);
            if (deleted) {
                log.debug("Deleted blob: {}", storedFilename);
            }
        } catch (IOException e) {
            throw new ApiExceptions.FileAccessException("Failed to delete file from storage: " + e.getMessage());
        }
    }

    @Override
    public boolean exists(String storedFilename) {
        Path target = resolveSafePath(storedFilename);
        return Files.exists(target);
    }
}
