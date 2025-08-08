package br.app.pdz.api.dto;

public record MineAccountRequest(
        String email,
        String secretKey
) {
}
