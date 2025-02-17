package com.template.auth.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.template.auth.entity.User;
import com.template.auth.exception.JWTException;
import com.template.auth.exception.UnauthorizedException;
import com.template.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Serviço responsável por gerar, validar e extrair informações do usuário de um JSON WebToken (JWT).
 */
@RequiredArgsConstructor
@Service
public class TokenService {
    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);
    private static final String CLASS = "[ TOKEN SERVICE ]";
    private static final String ISSUER = "API Template";

    private final UserRepository userRepository;

    /**
     * Tempo de expiração para o JWT gerado, especificado como uma string.
     */
    @Value("${template.jwt.expiration}")
    private String expiration;

    /**
     * Chave secreta usada para assinar o JWT.
     */
    @Value("${template.jwt.secret}")
    private String jwtSecret;

    /**
     * Gera um JWT com base no objeto de autenticação fornecido.
     *
     * @param auth O objeto de autenticação contendo os detalhes do usuário.
     * @return O JWT gerado como uma string.
     */
    public String generateToken(Authentication auth) {
        User user = (User) auth.getPrincipal();
        Date today = new Date();
        Date expirationDate = new Date(today.getTime() + Long.parseLong(expiration));

        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(user.getId().toString())
                .withIssuedAt(today)
                .withExpiresAt(expirationDate)
                .sign(Algorithm.HMAC256(jwtSecret));
    }

    /**
     * Valida um token JWT.
     *
     * @param token O token JWT a ser validado.
     * @return true se o token for válido, false caso contrário.
     */
    public Boolean validatesToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(jwtSecret)) // Usa a chave secreta
                    .build()
                    .verify(token);
            return true;
        } catch (JWTVerificationException e) {
            LOG.error("{} - [ validatesToken ] - TOKEN INVÁLIDO: {}", CLASS, e.getMessage());
            return false;
        }
    }

    /**
     * Extrai o ID do usuário do token JWT.
     *
     * @param token O token JWT do qual extrair o ID do usuário.
     * @return O ID do usuário extraído do token.
     */
    public Long getUserId(String token) {
        return Long.parseLong(JWT.require(Algorithm.HMAC256(jwtSecret))
                .build()
                .verify(token)
                .getSubject());
    }

    /**
     * Valida requisições públicas.
     *
     * @param path  O caminho da requisição.
     * @param token O token JWT da requisição.
     * @return true se a requisição for pública, false caso contrário.
     */
    public boolean validatePublicRequests(String path, String token) {
        return token == null && path.contains("/users/add");
    }

    /**
     * Valida o token, retornando true ou false.
     */
    public void validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(jwtSecret)) // Usa a chave secreta
                    .withIssuer(ISSUER)
                    .build()
                    .verify(token)
                    .getSubject(); // Se o token for válido, retorna o subject
        } catch (JWTVerificationException e) {
            String errorMessage = MessageFormat.format("{0} - [ validateToken ] - ERRO AO VALIDAR O TOKEN: {1}", CLASS, e.getMessage());
            LOG.error(errorMessage, e);
            throw new JWTException(errorMessage);
        }
    }

    /**
     * Obtém o usuário associado a um token.
     *
     * @param token O token JWT do qual extrair o usuário.
     * @return O nome do usuário extraído do token.
     */
    public String getUser(String token) {
        try {
            return JWT.require(Algorithm.HMAC256(jwtSecret))
                    .withIssuer(ISSUER)
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException e) {
            String errorMessage = MessageFormat.format("{0} - [ getUser ] - ERRO AO OBTER USUÁRIO DO TOKEN: {1}", CLASS, e.getMessage());
            LOG.error(errorMessage, e);
            throw new JWTException(errorMessage);
        }
    }

    /**
     * Valida a autorização de um usuário com base no caminho e token fornecidos.
     *
     * @param path  O caminho a ser acessado.
     * @param token O token JWT do usuário.
     */
    public void validateAuthorization(String path, String token) {
        Optional.ofNullable(this.getUser(token))
                .map(userId -> {
                    List<String> splitPath = List.of(path.split("/"));
                    String delimiter = path.startsWith("/") ? "/" : "";
                    String pathWithoutPrefix = delimiter + splitPath.stream().skip(2).collect(Collectors.joining("/"));

                    if (!userRepository.verificaPermissaoUsuarioEndpoint(Long.parseLong(userId), pathWithoutPrefix)) {
                        throw new UnauthorizedException("USUÁRIO SEM PERMISSÃO AO ENDPOINT");
                    }

                    return true;
                })
                .orElseThrow(() -> {
                    LOG.error("USUÁRIO NÃO ENCONTRADO COM O TOKEN FORNECIDO");
                    return new UnauthorizedException("USUÁRIO NÃO ENCONTRADO COM O TOKEN FORNECIDO");
                });
    }
}
