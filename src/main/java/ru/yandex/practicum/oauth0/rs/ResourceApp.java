package ru.yandex.practicum.oauth0.rs;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Resource server: validates access tokens and serves a protected payments API. It owns no
 * database (only the shared JWT secret + Redis revocation lookups), so the JPA/datasource
 * auto-configuration is excluded. Listens on port 8081 by default (override with SERVER_PORT).
 */
@SpringBootApplication(
        scanBasePackages = {
                "ru.yandex.practicum.oauth0.rs",
                "ru.yandex.practicum.oauth0.common"
        },
        exclude = {
                DataSourceAutoConfiguration.class,
                HibernateJpaAutoConfiguration.class,
                JpaRepositoriesAutoConfiguration.class
        })
public class ResourceApp {

    public static void main(String[] args) {
        new SpringApplicationBuilder(ResourceApp.class)
                .properties("server.port=8081")
                .run(args);
    }
}
