package br.app.pdz.api.exception;

import org.springframework.http.HttpStatus;

public class ProfilePictureException extends ExceptionWithHttpCode {


    public ProfilePictureException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
