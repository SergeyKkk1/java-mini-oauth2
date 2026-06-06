package ru.yandex.practicum.oauth0.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.yandex.practicum.oauth0.auth.model.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    /**
     * Invalidates an entire token family in one statement. Used when a rotated (already-used)
     * refresh token is replayed — the spec requires revoking every token in the family.
     */
    @Modifying
    @Query("update RefreshToken r set r.rotated = true where r.familyId = :familyId")
    int markFamilyRotated(@Param("familyId") String familyId);
}
