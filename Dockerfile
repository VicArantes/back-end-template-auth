FROM maven:3.9.8 AS build
COPY . /app
WORKDIR /app
RUN mvn clean package

FROM openjdk:24-slim
WORKDIR /app
ENV DB_USERNAME=template-admin
ENV DB_PASSWORD=template-admin-password
COPY --from=build /app/target/template-auth-0.0.1-SNAPSHOT.jar /app/template-auth.jar
ENTRYPOINT ["java", "-jar", "template-auth.jar"]