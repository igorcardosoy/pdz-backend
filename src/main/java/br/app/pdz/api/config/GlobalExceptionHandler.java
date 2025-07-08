package br.app.pdz.api.config;

import br.app.pdz.api.exception.ExceptionWithHttpCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception ex) {
        return new ResponseEntity<>("Error: " +  ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(ExceptionWithHttpCode.class)
    public ResponseEntity<String> handleExceptionWithHttpCode(ExceptionWithHttpCode ex) {
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body("Error: " + ex.getMessage());
    }


}
