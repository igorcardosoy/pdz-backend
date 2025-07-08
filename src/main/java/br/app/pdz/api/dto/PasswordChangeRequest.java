package br.app.pdz.api.dto;

public record PasswordChangeRequest(
        String email,
        String oldPassword,
        String newPassword
) { }
