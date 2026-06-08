package ru.yandex.practicum.oauth0.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "clients")
@Getter
@Setter
@NoArgsConstructor
public class Client {

    /** The client_id, supplied in the Basic auth header for the client_credentials */
    @Id
    private String id;

    @Column(name = "client_secret_hash", nullable = false)
    private String clientSecretHash;

    @Column
    private String info;
}
