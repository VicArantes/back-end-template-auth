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
 * Entidade que representa uma role.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "roles")
public class Role implements GrantedAuthority {

    /**
     * Identificador único da role.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Nome da role.
     */
    @Column(name = "tx_nome", unique = true)
    @ColumnTransformer(write = "UPPER(?)")
    @NotBlank
    private String nome;

    /**
     * Lista dos grupos de acesso da role.
     */
    @OneToMany(fetch = FetchType.EAGER)
    private Set<GrupoAcesso> grupoAcesso;

    @Override
    public String getAuthority() {
        return this.getNome();
    }

}