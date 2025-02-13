package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnTransformer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Set;

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
     * Username do usuário.
     */
    @Column(name = "tx_username", unique = true)
    @NotBlank
    private String username;

    /**
     * Password do usuário.
     */
    @Column(name = "tx_password")
    @NotBlank
    private String password;

    /**
     * Email do usuário.
     */
    @Column(name = "tx_email", unique = true)
    @ColumnTransformer(write = "LOWER(?)")
    @NotBlank
    private String email;

    /**
     * Identificador para verificar se o usuário está ativo.
     */
    @Column(name = "bl_ativo")
    @NotNull
    private boolean ativo;

    /**
     * Lista de roles do usuário.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @NotEmpty
    private Set<Role> roles;

    /**
     * Pega todas as roles do usuário.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.getRoles();
    }

    /**
     * Verifica se a conta do usuário não está expirada.
     */
    @Override
    public boolean isAccountNonExpired() {
        return this.isAtivo();
    }

    /**
     * Verifica se a conta do usuário não está bloqueada.
     */
    @Override
    public boolean isAccountNonLocked() {
        return this.isAtivo();
    }

    /**
     * Verifica se as credencias do usuário não estão expiradas.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Verifica se o usuário está habilitado.
     */
    @Override
    public boolean isEnabled() {
        return this.isAtivo();
    }
}
