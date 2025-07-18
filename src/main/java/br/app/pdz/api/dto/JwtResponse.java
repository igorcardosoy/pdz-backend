package br.app.pdz.api.dto;

public record JwtResponse(
        String token,
        Long id,
        String discordId,
        String username,
        java.util.List<String> roles
) {
}
