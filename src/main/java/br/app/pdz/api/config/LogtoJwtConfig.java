package br.app.pdz.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
public class LogtoJwtConfig {

    @Value("${pdz.security.logto.issuer-uri}")
    private String issuerUri;

    @Value("${pdz.security.logto.audience}")
    private String audience;

    @Value("${pdz.security.logto.roles-claim:}")
    private String rolesClaim;

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        List<String> audiences = Stream.of(audience.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .collect(Collectors.toList());
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(audiences);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator));
        return decoder;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
        scopes.setAuthorityPrefix("SCOPE_");
        scopes.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>(scopes.convert(jwt));
            for (String role : extractRoles(jwt)) {
                authorities.add(new SimpleGrantedAuthority(normalizeRole(role)));
            }
            return authorities;
        });
        return converter;
    }

    private List<String> extractRoles(Jwt jwt) {
        List<String> claimNames = new ArrayList<>();
        if (rolesClaim != null && !rolesClaim.isBlank()) {
            claimNames.add(rolesClaim.trim());
        } else {
            claimNames.add("roles");
            claimNames.add("role_names");
            claimNames.add("https://schemas.logto.io/claims/roles");
        }

        for (String claimName : claimNames) {
            Object claim = jwt.getClaims().get(claimName);
            List<String> roles = toStringList(claim);
            if (!roles.isEmpty()) {
                return roles;
            }
        }

        return List.of("user");
    }

    private List<String> toStringList(Object claim) {
        if (claim instanceof Collection<?> collection) {
            return collection.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .filter(value -> !value.isBlank())
                .toList();
        }

        if (claim instanceof String value) {
            return Stream.of(value.split("[ ,]+"))
                .map(String::trim)
                .filter(v -> !v.isBlank())
                .toList();
        }

        return List.of();
    }

    private String normalizeRole(String role) {
        String cleaned = role.trim();
        if (cleaned.isEmpty()) {
            return "ROLE_USER";
        }
        if (cleaned.toUpperCase(Locale.ROOT).startsWith("ROLE_")) {
            return cleaned.toUpperCase(Locale.ROOT);
        }
        return "ROLE_" + cleaned.toUpperCase(Locale.ROOT);
    }
}
