package br.app.pdz.api.repository;

import br.app.pdz.api.model.Whitelist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WhitelistRepository extends JpaRepository<Whitelist, Long> {

    boolean existsByDiscordUsername(String discordUsername);

    void deleteByDiscordUsername(String discordUsername);
}