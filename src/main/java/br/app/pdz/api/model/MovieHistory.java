package br.app.pdz.api.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "movie_history")
@Data
@NoArgsConstructor
public class MovieHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String title;

    @Column(length = 2000)
    private String description;

    @Column(length = 1000)
    private String link;

    private Long movieSize;

    private Integer seeders;
    private Integer peers;
    private String tracker;
    private String trackerId;
    private String publishDate;

    // Simplificando pra string contendo valores separados por vírgula para não criar tabela extra se não precisar,
    // ou mantemos o padrão relacional. Vamos de string pra facilitar.
    private String category;

    private String categoryDesc;

    @Column(length = 1000)
    private String details;

    @Column(length = 2000)
    private String magnetUri;

    private LocalDateTime downloadedAt;
}

