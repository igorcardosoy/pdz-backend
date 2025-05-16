package br.app.pdz.api.model.exeption;

import org.springframework.http.HttpStatus;

public class RoleNotFoundException extends ExceptionWithHttpCode {

    public RoleNotFoundException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
