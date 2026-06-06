# syntax=docker/dockerfile:1

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B -DskipTests package

# ---- Runtime stage: one image that can run either service via the APP env var ----
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/target/oauth-zero-*-auth.jar /app/auth.jar
COPY --from=build /workspace/target/oauth-zero-*-rs.jar   /app/rs.jar
COPY config ./config

# APP selects which service to run: "auth" (port 9000) or "rs" (port 8081).
ENV APP=auth
ENTRYPOINT ["sh", "-c", "java -jar /app/${APP}.jar"]
