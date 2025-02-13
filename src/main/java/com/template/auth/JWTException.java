package com.template.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class JWTException extends RuntimeException {

    public JWTException(String message) {
        super(message);
    }
}