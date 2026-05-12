package br.app.pdz.api.dto;

import java.util.List;

public record VideoInfoDTO(
        String title,
        Integer duration,
        List<FormatInfoDTO> formats
) {}

