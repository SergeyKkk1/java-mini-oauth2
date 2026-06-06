package ru.yandex.practicum.oauth0.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {

    /** The token's jti (also the {@code jti} claim of the rt+jwt). */
    @Id
    private String id;

    @Column(name = "user_id")
    private Long userId;

    /** Null for the password grant, which carries no client credential. */
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "family_id", nullable = false)
    private String familyId;

    @Column(nullable = false)
    private Instant exp;

    @Column(nullable = false)
    private boolean rotated;
}
