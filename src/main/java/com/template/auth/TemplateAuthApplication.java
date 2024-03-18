package com.template.auth;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Class responsável pela inicialização do projeto.
 */
@SpringBootApplication
@OpenAPIDefinition(servers = {@Server(url = "/template-auth/", description = "Default Server URL")})
public class TemplateAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(TemplateAuthApplication.class, args);
    }

}
