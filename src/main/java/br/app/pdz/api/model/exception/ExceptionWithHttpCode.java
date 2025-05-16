package br.app.pdz.api.model.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ExceptionWithHttpCode extends RuntimeException {
    private final HttpStatus httpStatus;
    public ExceptionWithHttpCode(String message, HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
    }

}
