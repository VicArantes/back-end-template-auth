package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

/**
 * Entidade que representa um user.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "users")
public class User implements UserDetails {

    /**
     * Identificador único do user.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Username do user.
     */
    @Column(name = "tx_username", unique = true)
    @NotBlank
    private String username;

    /**
     * Password do user.
     */
    @Column(name = "tx_password")
    @NotBlank
    private String password;

    /**
     * Lista de authorities do user.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @NotEmpty
    private List<Authority> authorities;

    /**
     * Verifica se a conta do user não está expirada.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Verifica se a conta do user não está bloqueada.
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Verifica se as credencias do user não estão expiradas.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Verifica se o user está habilitado.
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
