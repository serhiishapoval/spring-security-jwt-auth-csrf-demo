package com.security.demo.repository;

import com.security.demo.model.RoleEntity;
import com.security.demo.model.RoleEnum;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
  Optional<RoleEntity> findByRole(RoleEnum roleEnum);
}
