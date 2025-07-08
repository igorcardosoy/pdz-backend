package br.app.pdz.api.service;

import br.app.pdz.api.exception.UserAlreadyExistsException;
import br.app.pdz.api.exception.UserNotInWhiteList;
import br.app.pdz.api.model.Whitelist;
import br.app.pdz.api.repository.WhitelistRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Log4j2
public class WhitelistService {

    private final WhitelistRepository whitelistRepository;

    public WhitelistService(WhitelistRepository whitelistRepository) {
        this.whitelistRepository = whitelistRepository;
    }

    public boolean isUserWhitelisted(String discordUsername) {
        return whitelistRepository.existsByDiscordUsername(discordUsername);
    }

    public void addToWhitelist(String discordUsername, String addedBy) {
        if (whitelistRepository.existsByDiscordUsername(discordUsername)) {
            throw new UserAlreadyExistsException("User is already in whitelist", HttpStatus.CONFLICT);
        }

        Whitelist whitelist = new Whitelist();
        whitelist.setDiscordUsername(discordUsername);
        whitelist.setAddedBy(addedBy);

        whitelistRepository.save(whitelist);
        log.info("User {} added to whitelist by {}", discordUsername, addedBy);
    }

    @Transactional
    public void removeFromWhitelist(String discordUsername) {
        if (!whitelistRepository.existsByDiscordUsername(discordUsername)) {
            throw new UserNotInWhiteList("User is not in whitelist", HttpStatus.NOT_FOUND);
        }

        whitelistRepository.deleteByDiscordUsername(discordUsername);
        log.info("User {} removed from whitelist", discordUsername);
    }

    public List<Whitelist> getAllWhitelistedUsers() {
        return whitelistRepository.findAll();
    }
}