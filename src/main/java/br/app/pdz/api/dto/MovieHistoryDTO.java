package br.app.pdz.api.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
public class MovieHistoryDTO {
    private Long id;
    private MovieDTO movie;
    private LocalDateTime downloadedAt;
}


