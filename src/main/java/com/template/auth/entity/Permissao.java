package com.template.auth.entity;

import jakarta.persistence.*;
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
     * Descrição da permissão.
     */
    @Column(name = "tx_descricao")
    private String descricao;

    /**
     * URI da permissão.
     */
    @Column(name = "tx_uri")
    private String uri;

}