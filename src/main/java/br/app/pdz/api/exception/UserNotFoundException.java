package br.app.pdz.api.exception;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends ExceptionWithHttpCode {

    public UserNotFoundException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
