# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build & Package application
# ------------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /workspace

# Cache dependencies layer
COPY pom.xml .
COPY .mvn .mvn
RUN ./mvnw dependency:go-offline -B || true

# Copy source code and build production jar
COPY src src
RUN apt-get update && apt-get install -y maven
RUN mvn clean package -DskipTests -B

# ------------------------------------------------------------------------------
# Stage 2: Minimal, Hardened Runtime Image
# ------------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy AS runtime
WORKDIR /app

# Create unprivileged system user for security compliance
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Create storage directory for encrypted files with safe permissions
RUN mkdir -p /app/locked_files && chown -R appuser:appgroup /app

# Copy executable jar from builder stage
COPY --from=builder /workspace/target/securefilelocker-*.jar /app/app.jar
RUN chown appuser:appgroup /app/app.jar

USER appuser

ENV SERVER_PORT=8083 \
    LOCKER_DIR=/app/locked_files \
    JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"

EXPOSE 8083

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:8083/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
