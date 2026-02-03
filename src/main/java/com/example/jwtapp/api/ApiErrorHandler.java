package com.example.jwtapp.api;

import com.example.jwtapp.deser.InsecureDeserializationException;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class ApiErrorHandler {

    @ExceptionHandler(DataAccessException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleDataAccess(DataAccessException ex) {
        return Map.of(
                "error", "database_error",
                "message", "Upit nije prošao. (Provjeri unos ili koristi sigurni endpoint.)"
        );
    }

    @ExceptionHandler(InsecureDeserializationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleDeserialization(InsecureDeserializationException ex) {
        return Map.of(
                "error", "deserialization_error",
                "message", ex.getMessage()
        );
    }
}
