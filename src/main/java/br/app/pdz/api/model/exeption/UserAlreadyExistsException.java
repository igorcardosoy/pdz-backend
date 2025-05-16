package br.app.pdz.api.model.exeption;

import org.springframework.http.HttpStatus;

public class UserAlreadyExistsException extends ExceptionWithHttpCode {

    public UserAlreadyExistsException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
