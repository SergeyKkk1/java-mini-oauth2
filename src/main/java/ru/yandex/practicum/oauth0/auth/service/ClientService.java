package ru.yandex.practicum.oauth0.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.config.ClientScopeProperties;
import ru.yandex.practicum.oauth0.auth.exception.OAuthException;
import ru.yandex.practicum.oauth0.auth.model.Client;
import ru.yandex.practicum.oauth0.auth.repository.ClientRepository;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientService {

    private final ClientRepository clientRepository;
    private final ClientScopeProperties clientScopeProperties;

    /** Verifies clientId/secret against the stored BCrypt hash. */
    @Transactional(readOnly = true)
    public Client authenticate(String clientId, String clientSecret) {
        log.debug("Authenticating client '{}'", clientId);
        Client client = clientRepository.findById(clientId).orElseThrow(OAuthException::invalidClient);
        if (!BCrypt.checkpw(clientSecret, client.getClientSecretHash())) {
            throw OAuthException.invalidClient();
        }
        return client;
    }

    /** Configured scopes for a confidential client (see {@link ClientScopeProperties}). */
    public Set<String> scopesFor(String clientId) {
        String configured = clientScopeProperties.getClientScopes().getOrDefault(clientId, "");
        if (configured.isBlank()) {
            log.warn("No scopes configured for client '{}'", clientId);
            return Collections.emptySet();
        }
        return new TreeSet<>(Arrays.asList(configured.trim().split("\\s+")));
    }
}
