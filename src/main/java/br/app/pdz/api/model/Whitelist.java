package br.app.pdz.api.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "whitelist")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Whitelist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "discord_username", nullable = false, unique = true)
    private String discordUsername;

    @Column(name = "added_by")
    private String addedBy;

    @Column(name = "created_at")
    private java.time.LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = java.time.LocalDateTime.now();
    }
}