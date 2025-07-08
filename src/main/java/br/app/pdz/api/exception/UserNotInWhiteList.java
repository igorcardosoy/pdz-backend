package br.app.pdz.api.exception;

import org.springframework.http.HttpStatus;

public class UserNotInWhiteList extends ExceptionWithHttpCode {

    public UserNotInWhiteList(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
    }
}
