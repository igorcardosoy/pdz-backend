package br.app.pdz.api.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller para debug de autenticação JWT
 */
@RestController
@RequestMapping("/pdz-api/debug")
@Log4j2
public class DebugAuthController {

    /**
     * Endpoint para debug — mostra o conteúdo do token recebido
     */
    @GetMapping("/me")
    public Map<String, Object> debugMe(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication == null) {
            response.put("authenticated", false);
            response.put("principal", null);
            return response;
        }

        response.put("authenticated", authentication.isAuthenticated());
        response.put("principal", authentication.getPrincipal());
        response.put("principals_name", authentication.getName());
        response.put("authorities", authentication.getAuthorities());

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            Map<String, Object> jwtInfo = new HashMap<>();
            jwtInfo.put("subject", jwt.getSubject());
            jwtInfo.put("issuer", jwt.getIssuer());
            jwtInfo.put("audience", jwt.getAudience());
            jwtInfo.put("expiry", jwt.getExpiresAt());
            jwtInfo.put("claims", jwt.getClaims());
            response.put("jwt", jwtInfo);
        }

        log.info("Debug me called: {}", response);
        return response;
    }
}

