package br.app.pdz.api.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "mine_accounts")
@Data
public class MineAccount {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(unique = true)
        private String email;

        @Column(unique = true)
        private String secretKey;
}
