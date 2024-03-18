package com.template.auth.config;

import com.template.auth.entity.User;
import com.template.auth.service.UserService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Esta classe é um filtro de autenticação que estende a classe OncePerRequestFilter do Spring.
 */
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {
    private final TokenService tokenService;
    private final UserService userService;

    /**
     * Recupera o token de autenticação do cabeçalho da solicitação.
     *
     * @param request O objeto HttpServletRequest da solicitação.
     * @return O token de autenticação.
     */
    private String recoveryToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");

        if (token == null || !token.startsWith("Bearer ")) {
            return null;
        } else {
            return token.substring(7);
        }
    }

    /**
     * Autentica o usuário com base no token de autenticação.
     *
     * @param token O token de autenticação.
     */
    private void authenticateUser(String token) {
        User user = userService.findById(tokenService.getUserId(token));
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
    }

    /**
     * Executa o filtro durante a solicitação HTTP.
     *
     * @param request     O objeto HttpServletRequest da solicitação.
     * @param response    O objeto HttpServletResponse da resposta.
     * @param filterChain O objeto FilterChain usado para invocar os filtros subsequentes na cadeia.
     * @throws ServletException Se ocorrer um erro durante o processamento da solicitação.
     * @throws IOException      Se ocorrer um erro de I/O durante o processamento da solicitação.
     */
    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull FilterChain filterChain) throws ServletException, IOException {
        String token = this.recoveryToken(request);
        boolean isValidToken = tokenService.validatesToken(token);

        if (isValidToken) {
            this.authenticateUser(token);
        }

        filterChain.doFilter(request, response);
    }
}