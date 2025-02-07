package com.template.auth.config;

import com.template.auth.entity.User;
import com.template.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Esta classe é um serviço de autenticação que implementa a interface UserDetailsService do Spring Security.
 */
@RequiredArgsConstructor
@Service
public class AuthenticationService implements UserDetailsService {
    private final UserRepository repository;

    /**
     * Carrega os detalhes do usuário com base no nome de usuário fornecido.
     *
     * @param username O nome de usuário do usuário a ser carregado.
     * @return Os detalhes do usuário como um objeto UserDetails.
     * @throws UsernameNotFoundException Se o usuário com o nome de usuário fornecido não for encontrado.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = repository.findByUsername(username);

        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("Usuário não encontrado!");
        } else {
            return optionalUser.get();
        }
    }

}
