package br.app.pdz.api.exception;

import org.springframework.http.HttpStatus;

public class PasswordException extends ExceptionWithHttpCode {

    public PasswordException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
