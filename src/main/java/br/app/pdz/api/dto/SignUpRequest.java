package br.app.pdz.api.dto;

public record SignUpRequest(
        String username,
        String email,
        String password
) { }
