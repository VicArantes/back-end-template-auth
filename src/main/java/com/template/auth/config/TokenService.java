package com.template.auth.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.template.auth.UnauthorizedException;
import com.template.auth.entity.User;
import com.template.auth.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;

/**
 * Serviço responsável por gerar, validar e extrair informações do usuário de um JSON WebToken (JWT).
 */
@RequiredArgsConstructor
@Service
public class TokenService {
    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);
    private static final String CLASS = "[ TOKEN SERVICE ]";

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
     * Gera uma chave secreta HMAC a partir de um segredo codificado em Base64.
     * <p>
     * Este método utiliza a string {@code jwtSecret}, que deve estar codificada em Base64,
     * para decodificar e criar uma chave secreta compatível com algoritmos HMAC,
     * como HS256, HS384 ou HS512. A chave gerada será utilizada para assinar e validar tokens JWT.
     *
     * @return Uma instância de {@link javax.crypto.SecretKey} derivada do segredo codificado em Base64.
     * @throws IllegalArgumentException Se {@code jwtSecret} não for uma string válida em Base64
     *                                  ou não atender aos requisitos mínimos de tamanho do algoritmo.
     */
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

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

        return Jwts.builder()
                .issuer("API Template")
                .subject(user.getId().toString())
                .issuedAt(today)
                .expiration(expirationDate)
                .signWith(this.getSecretKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Valida um token JWT.
     *
     * @param token O token JWT a ser validado.
     * @return true se o token for válido, false caso contrário.
     */
    public Boolean validatesToken(String token) {
        try {
            Jwts.parser().verifyWith(this.getSecretKey()).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
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
        return Long.parseLong(Jwts.parser().verifyWith(this.getSecretKey()).build().parseSignedClaims(token).getPayload().getSubject());
    }

    public boolean validatePublicRequests(String path, String token) {
        return token == null && path.contains("/users/add");
    }

    public boolean validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
            return JWT.require(algorithm)
                    .withIssuer("auth-gateway")
                    .build()
                    .verify(token)
                    .getSubject() != null;
        } catch (JWTVerificationException e) {
            LOG.error("{} - [ validateToken ] - Occurred an error to validate a token - ERROR [{}]", CLASS, e.getMessage());
            throw new JwtException(e.getMessage());
        }
    }

    private static boolean isAllowedToAccess(String path, User u) {
        return u.getRoles().stream().anyMatch(role -> role.getPermissoes().stream().anyMatch(permissao -> {
            if (path.matches(".*\\d.*")) {
                permissao.setUri(permissao.getUri().replace("{code}", ""));
            }
            return path.contains(permissao.getUri());
        }));
    }

    public String getUser(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
            return JWT.require(algorithm)
                    .withIssuer("auth-gateway")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException e) {
            LOG.error("{} - [ getUser ] - Occurred an error to get a user from token - ERROR [{}]", CLASS, e.getMessage());
            throw new JwtException(e.getMessage());
        }
    }

    public void validateAuthorization(String path, String token) {
        Optional.ofNullable(this.getUser(token))
                .map(user -> {
                    userRepository.findByUsername(user)
                            .map(u -> {
                                if (isAllowedToAccess(path, u))
                                    return true;

                                LOG.error("User has no authorization to access path [{}]", path);
                                throw new UnauthorizedException(String.format("User has no authorization to access path %s", path));
                            })
                            .orElseThrow(() -> {
                                LOG.error("User not found with login [{}]", user);
                                return new UnauthorizedException(String.format("User not found with login %s", user));
                            });

                    return true;
                })
                .orElseThrow(() -> {
                    LOG.error("User not found within token");
                    return new UnauthorizedException("User not found within token");
                });


    }

}
