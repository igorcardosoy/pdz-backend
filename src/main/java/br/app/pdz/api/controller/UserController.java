package br.app.pdz.api.controller;

import br.app.pdz.api.dto.LogtoUserProfileDTO;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@Log4j2
@RequestMapping("/pdz-api/users")
@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
public class UserController {
    @GetMapping("/me")
    public ResponseEntity<LogtoUserProfileDTO> me(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return ResponseEntity.status(401).build();
        }

        String username = firstNonBlank(
            jwt.getClaimAsString("username"),
            jwt.getClaimAsString("name"),
            jwt.getSubject()
        );

        List<String> roles = authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .toList();

        LogtoUserProfileDTO profile = new LogtoUserProfileDTO(
            jwt.getSubject(),
            username,
            jwt.getClaimAsString("email"),
            jwt.getClaimAsString("picture"),
            roles
        );

        return ResponseEntity.ok(profile);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
