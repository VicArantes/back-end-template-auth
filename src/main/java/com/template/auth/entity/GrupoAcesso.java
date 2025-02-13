package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entidade que representa um grupo de acesso.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "grupos_acesso")
public class GrupoAcesso {

    /**
     * Identificador único do grupo de acesso.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Rota do grupo de acesso.
     */
    @OneToOne
    @NotNull
    private Rota rota;

}