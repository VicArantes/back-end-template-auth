package com.template.auth.repository;

import com.template.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository para entidade User.
 */
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
