package com.template.auth.service;

import com.template.auth.entity.User;
import com.template.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Serviço para manipulação de users.
 */
@RequiredArgsConstructor
@Service
@Transactional
public class UserService {
    private final UserRepository repository;

    /**
     * Busca um user pelo ID.
     *
     * @param id o ID do user a ser buscado
     * @return o user encontrado
     * @throws EntityNotFoundException se o user não for encontrado
     */
    public User findById(Long id) {
        return repository.findById(id).orElseThrow(() -> new EntityNotFoundException("User não encontrado"));
    }

}
