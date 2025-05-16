package br.app.pdz.api.dto;

public record ProfilePictureDTO<T>(
        T profilePicture,
        String contentType,
        String length
) {
}
