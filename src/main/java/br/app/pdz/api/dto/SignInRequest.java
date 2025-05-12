package br.app.pdz.api.dto;

public record SignInRequest(
        String username,
        String password
) { }
