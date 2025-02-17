package com.template.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entidade que representa uma permissão.
 */
@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
@Table(name = "permissoes")
public class Permissao {

    /**
     * Identificador único da permissão.
     */
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    /**
     * Nome da permissão.
     */
    @Column(name = "tx_nome")
    @NotBlank
    private String nome;

    /**
     * Endpoint da permissão.
     */
    @Column(name = "tx_endpoint", unique = true)
    @NotBlank
    private String endpoint;


    /**
     * Identificador para verificar se a permissão está ativa.
     */
    @Column(name = "bl_ativo")
    @NotNull
    private boolean ativo;

}