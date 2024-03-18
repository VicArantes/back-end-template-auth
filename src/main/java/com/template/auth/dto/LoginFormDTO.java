package com.template.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Record que representa um LoginFormDTO.
 *
 * @param username Username do LoginFormDTO.
 * @param password Password do LoginFormDTO.
 */
public record LoginFormDTO(@NotBlank String username, @NotBlank String password) {

}
