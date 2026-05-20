package br.app.pdz.api.dto;

import java.util.List;

public record LogtoUserProfileDTO(
    String sub,
    String username,
    String email,
    String picture,
    List<String> roles
) {}
