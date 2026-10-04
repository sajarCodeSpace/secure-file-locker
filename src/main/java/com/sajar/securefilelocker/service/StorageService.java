package com.sajar.securefilelocker.service;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Storage abstraction allowing files to be saved, loaded, and deleted.
 * Decouples domain logic from local file system I/O, enabling alternate
 * backends such as AWS S3 or MinIO.
 */
public interface StorageService {

    /**
     * Stores data from an input stream under a designated storage identifier.
     */
    void store(String storedFilename, InputStream inputStream);

    /**
     * Opens an InputStream to read the stored file bytes.
     */
    InputStream load(String storedFilename);

    /**
     * Deletes a stored file if it exists.
     */
    void delete(String storedFilename);

    /**
     * Checks if a file exists in the storage layer.
     */
    boolean exists(String storedFilename);
}
