package br.app.pdz.api.repository;

import br.app.pdz.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByUsernameAndEmail(String username, String email);

    Optional<User> findByDiscordId(String discordId);

    Boolean existsByUsername(String username);

    Boolean existsByUsernameAndEmail(String username, String email);

    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}
