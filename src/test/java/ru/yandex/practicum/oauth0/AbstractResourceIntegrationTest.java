package ru.yandex.practicum.oauth0;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import ru.yandex.practicum.oauth0.rs.ResourceApp;

@SpringBootTest(classes = ResourceApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractResourceIntegrationTest extends AbstractIntegrationTest {
}
