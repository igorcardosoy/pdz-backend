package br.app.pdz.api.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Entity
@Table(name = "roles")
@Data
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Setter(AccessLevel.NONE)
    @Getter(AccessLevel.NONE)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(unique = true)
    @Setter(AccessLevel.NONE)
    private EnumRole name;
}
