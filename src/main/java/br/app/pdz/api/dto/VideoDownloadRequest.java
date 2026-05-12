package br.app.pdz.api.dto;

public record VideoDownloadRequest(
        String url,
        String resolution,
        String format
) {}
