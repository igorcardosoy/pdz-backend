package br.app.pdz.api.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

public class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    private final List<String> audiences;

    public AudienceValidator(List<String> audiences) {
        this.audiences = audiences;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (audiences == null || audiences.isEmpty()) {
            return OAuth2TokenValidatorResult.success();
        }
        List<String> tokenAudiences = jwt.getAudience();
        if (tokenAudiences != null && tokenAudiences.stream().anyMatch(audiences::contains)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(
                "invalid_token",
                "Missing required audience. Expected one of: " + String.join(",", audiences),
                null
        );
        return OAuth2TokenValidatorResult.failure(error);
    }
}
