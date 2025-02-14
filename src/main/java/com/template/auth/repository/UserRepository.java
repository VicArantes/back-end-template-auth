package com.template.auth.repository;

import com.template.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * Repository para entidade User.
 */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    @Query(value = "SELECT                                                                                              " +
            "           COUNT(*) > 0                                                                                    " +
            "       FROM                                                                                                " +
            "           users u                                                                                         " +
            "           INNER JOIN users_roles ur ON ur.user_id = u.id                                                  " +
            "           INNER JOIN roles r ON r.id = ur.roles_id                                                        " +
            "           INNER JOIN roles_grupo_acesso rga ON rga.role_id = r.id                                         " +
            "           INNER JOIN grupos_acesso ga ON ga.id = rga.grupo_acesso_id                                      " +
            "           INNER JOIN rotas r2 ON r2.id = ga.rota_id                                                       " +
            "           INNER JOIN rotas_permissoes rp ON rp.rota_id = r2.id                                            " +
            "           INNER JOIN permissoes p ON p.id = rp.permissoes_id                                              " +
            "       WHERE                                                                                               " +
            "           u.id = :userId                                                                                  " +
            "           and :requestedPath ~ ('^' || REGEXP_REPLACE(p.tx_endpoint, '\\{[^/]+\\}', '[^/]+', 'g') || '$') ", nativeQuery = true)
    boolean verificaPermissaoUsuarioEndpoint(@Param("userId") long userId, @Param("requestedPath") String requestedPath);

}