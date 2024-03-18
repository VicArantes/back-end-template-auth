package com.template.auth.config;

import com.template.auth.dto.ErrorResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Controlador para lidar com os erros.
 */
@ControllerAdvice
public class AdviceExceptionController extends ResponseEntityExceptionHandler {

    /**
     * Função responsável por retornar a mensagem de erro.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> getError(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponseDTO(ex.getMessage()));
    }

}
