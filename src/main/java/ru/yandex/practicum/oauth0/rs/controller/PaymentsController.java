package ru.yandex.practicum.oauth0.rs.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.rs.filter.JwtAuthFilter;
import ru.yandex.practicum.oauth0.rs.security.ResourcePrincipal;
import ru.yandex.practicum.oauth0.rs.security.ScopeChecker;

import java.util.List;
import java.util.Map;

/**
 * Sample protected resource. Authentication (401) is handled by {@code JwtAuthFilter}; these
 * methods only enforce per-endpoint scope (403) before returning data.
 */
@Slf4j
@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
public class PaymentsController {

    private static final String READ_SCOPE = "payments:read";
    private static final String WRITE_SCOPE = "payments:write";

    private final ScopeChecker scopeChecker;

    @GetMapping
    public Map<String, Object> list(@RequestAttribute(JwtAuthFilter.PRINCIPAL_ATTRIBUTE) ResourcePrincipal principal) {
        scopeChecker.require(principal, READ_SCOPE);
        log.info("Returning payments for subject={}", principal.subject());
        return Map.of(
                "subject", principal.subject(),
                "payments", List.of(
                        Map.of("id", 1, "amount", 4200, "currency", "USD"),
                        Map.of("id", 2, "amount", 1500, "currency", "EUR")));
    }

    @PostMapping
    public Map<String, Object> create(@RequestAttribute(JwtAuthFilter.PRINCIPAL_ATTRIBUTE) ResourcePrincipal principal,
                                      @RequestBody(required = false) Map<String, Object> payment) {
        scopeChecker.require(principal, WRITE_SCOPE);
        log.info("Accepting payment from subject={}: {}", principal.subject(), payment);
        return Map.of(
                "status", "created",
                "subject", principal.subject(),
                "payment", payment == null ? Map.of() : payment);
    }
}
