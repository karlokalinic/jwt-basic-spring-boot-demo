package com.example.jwtapp.deser;

public class InsecureDeserializationException extends RuntimeException {
    public InsecureDeserializationException(String message) {
        super(message);
    }

    public InsecureDeserializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
