package ru.yandex.practicum.oauth0;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import ru.yandex.practicum.oauth0.auth.AuthApp;

@SpringBootTest(classes = AuthApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractAuthIntegrationTest extends AbstractIntegrationTest {
}
