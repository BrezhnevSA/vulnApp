ARG MAVEN_IMAGE=maven:3.9.16-eclipse-temurin-11-noble
ARG TOMCAT_IMAGE=tomcat:9.0.120-jre11-temurin-noble

FROM ${MAVEN_IMAGE} AS builder

WORKDIR /build

COPY pom.xml ./
RUN mvn --batch-mode --no-transfer-progress dependency:go-offline

COPY src ./src
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM ${TOMCAT_IMAGE}

RUN rm -rf /usr/local/tomcat/webapps/*

COPY --from=builder /build/target/app.war /usr/local/tomcat/webapps/app.war

EXPOSE 8080
