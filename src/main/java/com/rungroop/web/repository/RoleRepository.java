package com.rungroop.web.repository;

import com.rungroop.web.models.Role;
import com.rungroop.web.models.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
