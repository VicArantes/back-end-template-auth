package com.template.auth.controller;

import com.template.auth.service.TokenService;
import com.template.auth.dto.LoginFormDTO;
import com.template.auth.dto.PathRequestDTO;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Esta classe é um controlador responsável por lidar com as solicitações de autenticação.
 */
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@RestController
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    /**
     * Autentica o usuário com base nas credenciais fornecidas e gera um token de autenticação.
     *
     * @param loginForm O objeto LoginFormDTO contendo o nome de usuário e a senha do usuário.
     * @return Uma ResponseEntity contendo o token de autenticação.
     */
    @PostMapping("/login")
    public ResponseEntity<String> autenticar(@RequestBody @Valid LoginFormDTO loginForm) {
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginForm.username(), loginForm.password()));
        return ResponseEntity.ok(tokenService.generateToken(auth));
    }

    @PutMapping("/validate/{token}")
    public ResponseEntity<Void> validate(@PathVariable String token, @RequestBody PathRequestDTO dto) {
        if (!tokenService.validatePublicRequests(dto.path(), token)) {
            tokenService.validateToken(token);
            tokenService.validateAuthorization(dto.path(), token);
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

}