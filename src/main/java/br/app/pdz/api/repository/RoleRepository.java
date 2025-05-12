package br.app.pdz.api.repository;

import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(EnumRole name);
}
