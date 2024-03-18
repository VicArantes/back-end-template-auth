package com.template.auth.config;

import com.template.auth.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Serviço responsável por gerar, validar e extrair informações do usuário de um JSON WebToken (JWT).
 */
@Service
public class TokenService {

    /**
     * Tempo de expiração para o JWT gerado, especificado como uma string.
     */
    @Value("${template.jwt.expiration}")
    private String expiration;

    /**
     * Chave secreta usada para assinar o JWT.
     */
    @Value("${template.jwt.secret}")
    private String secret;

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
                .setIssuer("API Template")
                .setSubject(user.getId().toString())
                .setIssuedAt(today)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, this.secret)
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
            Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
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
        return Long.parseLong(Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody().getSubject());
    }

}
