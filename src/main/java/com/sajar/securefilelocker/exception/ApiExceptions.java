package com.sajar.securefilelocker.exception;

/** Thrown on bad username/password at login, or username already taken at registration. */
public class ApiExceptions {

    public static class UsernameTakenException extends RuntimeException {
        public UsernameTakenException(String username) {
            super("Username already taken: " + username);
        }
    }

    public static class InvalidCredentialsException extends RuntimeException {
        public InvalidCredentialsException() {
            super("Invalid username or password");
        }
    }

    public static class FileAccessException extends RuntimeException {
        public FileAccessException(String message) {
            super(message);
        }
    }

    /** Thrown when the GCM auth tag fails to verify - i.e. wrong password, or the file was tampered with. */
    public static class WrongFilePasswordException extends RuntimeException {
        public WrongFilePasswordException() {
            super("Incorrect password or corrupted file");
        }
    }

    public static class ResourceNotFoundException extends RuntimeException {
        public ResourceNotFoundException(String message) {
            super(message);
        }
    }

    public static class TooManyRequestsException extends RuntimeException {
        public TooManyRequestsException(String message) {
            super(message);
        }
    }
}
