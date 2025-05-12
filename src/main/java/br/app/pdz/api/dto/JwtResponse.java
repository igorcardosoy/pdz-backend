package br.app.pdz.api.dto;

public record JwtResponse(
        String token,
        Long id,
        String username,
        java.util.List<String> roles
) {
    static String type = "Bearer";
}
