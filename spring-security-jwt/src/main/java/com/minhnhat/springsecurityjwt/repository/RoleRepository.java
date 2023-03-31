package com.minhnhat.springsecurityjwt.repository;

import com.minhnhat.springsecurityjwt.model.ERole;
import com.minhnhat.springsecurityjwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
