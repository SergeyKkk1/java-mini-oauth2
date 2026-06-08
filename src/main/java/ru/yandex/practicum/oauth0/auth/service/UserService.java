package ru.yandex.practicum.oauth0.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.exception.OAuthException;
import ru.yandex.practicum.oauth0.auth.model.Permission;
import ru.yandex.practicum.oauth0.auth.model.User;
import ru.yandex.practicum.oauth0.auth.repository.UserRepository;

import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    /** Verifies username/password against the stored BCrypt hash. */
    @Transactional(readOnly = true)
    public User authenticate(String username, String password) {
        log.debug("Authenticating user '{}'", username);
        User user = userRepository.findByUsernameWithRoles(username)
                .orElseThrow(OAuthException::invalidUserCredentials);
        if (!BCrypt.checkpw(password, user.getPasswordHash())) {
            throw OAuthException.invalidUserCredentials();
        }
        return user;
    }

    @Transactional(readOnly = true)
    public User getById(Long id) {
        log.debug("Loading user by id {}", id);
        return userRepository.findByIdWithRoles(id).orElseThrow(OAuthException::invalidUserCredentials);
    }

    /** Flattens the user's roles into the set of permission names used as token scopes. */
    public Set<String> scopesFor(User user) {
        Set<String> scopes = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toCollection(TreeSet::new));
        log.debug("Resolved scopes {} for user '{}'", scopes, user.getUsername());
        return scopes;
    }
}
