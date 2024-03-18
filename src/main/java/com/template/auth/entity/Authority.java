package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnTransformer;
import org.springframework.security.core.GrantedAuthority;

/**
 * Entidade que representa um perfil.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "authorities")
public class Authority implements GrantedAuthority {

    /**
     * Identificador único do perfil.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Authority Name do perfil.
     */
    @Column(name = "tx_authority_name", unique = true)
    @ColumnTransformer(write = "UPPER(?)")
    @NotBlank
    private String authorityName;

    @Override
    public String getAuthority() {
        return authorityName;
    }

}