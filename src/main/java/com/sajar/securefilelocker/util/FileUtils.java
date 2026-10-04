package com.sajar.securefilelocker.util;

import java.nio.file.Paths;

public final class FileUtils {

    private static final String DEFAULT_FILENAME = "unnamed_file";
    private static final int MAX_FILENAME_LENGTH = 255;

    private FileUtils() {}

    /**
     * Sanitizes an uploaded file's original name to prevent path traversal,
     * header injection (CRLF), and unexpected file system behavior.
     */
    public static String sanitizeFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            return DEFAULT_FILENAME;
        }

        // Normalize and extract only the final path segment
        String cleanName = Paths.get(filename).getFileName().toString();

        // Strip carriage returns, newlines, null bytes, and path separators
        cleanName = cleanName.replaceAll("[\\r\\n\\t\\u0000/\\\\]", "_").trim();

        // Remove dangerous leading dots
        cleanName = cleanName.replaceAll("^\\.+", "");

        if (cleanName.isBlank()) {
            cleanName = DEFAULT_FILENAME;
        }

        if (cleanName.length() > MAX_FILENAME_LENGTH) {
            cleanName = cleanName.substring(0, MAX_FILENAME_LENGTH);
        }

        return cleanName;
    }
}
