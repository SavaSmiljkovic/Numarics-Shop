package com.numarics.user.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@EnableConfigurationProperties(Properties.class)
public class Properties {

    private Url url;
    private Web web;
    private Admin admin;
    private Jwt jwt;

    @Getter
    @Setter
    public static class Url {

        private String register;
        private String login;

    }

    @Getter
    @Setter
    public static class Web {

        private String publicEndpoints;
        private String allowedOrigins;
        private String allowedMethods;
        private String allowedHeaders;

    }

    @Getter
    @Setter
    public static class Admin {

        private String username;
        private String password;

    }

    @Getter
    @Setter
    public static class Jwt {

        private String secret;
        private String prefix;
        private String header;
        private Claim claim;

        @Getter
        @Setter
        public static class Claim {

            private String roleTitle;
            private Role role;

            @Getter
            @Setter
            public static class Role {

                private String admin;
                private String user;

            }

        }

    }

}
