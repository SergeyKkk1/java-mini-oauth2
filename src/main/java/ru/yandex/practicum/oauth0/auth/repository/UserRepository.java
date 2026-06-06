package ru.yandex.practicum.oauth0.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.yandex.practicum.oauth0.auth.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Loads a user together with their roles and each role's permissions in a single query, so that
     * computing token scopes does not trigger N+1 lazy loads. {@code distinct} collapses the
     * cartesian-product rows produced by the nested fetch joins.
     */
    @Query("select distinct u from User u "
            + "left join fetch u.roles r "
            + "left join fetch r.permissions "
            + "where u.username = :username")
    Optional<User> findByUsernameWithRoles(@Param("username") String username);

    @Query("select distinct u from User u "
            + "left join fetch u.roles r "
            + "left join fetch r.permissions "
            + "where u.id = :id")
    Optional<User> findByIdWithRoles(@Param("id") Long id);
}
