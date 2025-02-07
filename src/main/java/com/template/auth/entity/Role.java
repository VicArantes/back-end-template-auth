package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnTransformer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

/**
 * Entidade que representa um perfil.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "roles")
public class Role implements GrantedAuthority {

    /**
     * Identificador único do perfil.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Authority Name do perfil.
     */
    @Column(name = "tx_nome", unique = true)
    @ColumnTransformer(write = "UPPER(?)")
    @NotBlank
    private String nome;

    /**
     * Lista das permissões da role.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Permissao> permissoes;

    @Override
    public String getAuthority() {
        return "";
    }

}