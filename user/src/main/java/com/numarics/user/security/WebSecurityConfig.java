package com.numarics.user.security;

import com.numarics.user.model.User;
import com.numarics.user.repository.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final UserRepository userRepository;
    private final Properties properties;

    public WebSecurityConfig(UserRepository userRepository, Properties properties) {
        this.userRepository = userRepository;
        this.properties = properties;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(properties.getWeb().getAllowedOrigins().split(",")));
        configuration.setAllowedMethods(Arrays.asList(properties.getWeb().getAllowedMethods().split(",")));
        configuration.setAllowedHeaders(Arrays.asList(properties.getWeb().getAllowedHeaders().split(",")));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                   .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .authorizeHttpRequests(auth -> auth.requestMatchers(properties.getWeb().getPublicEndpoints().split(",")).permitAll()
                                                      .anyRequest().authenticated())
                   .addFilterBefore(new JWTAuthenticationFilter(authenticationManager, userRepository, properties),
                                    UsernamePasswordAuthenticationFilter.class)
                   .build();
    }

    @Bean
    public ApplicationRunner initializer() {
        return args -> {
            if (userRepository.existsByUsername(properties.getAdmin().getUsername())) {
                User admin = new User();
                admin.setUsername(properties.getAdmin().getUsername());
                admin.setPassword(passwordEncoder().encode(properties.getAdmin().getPassword()));
                admin.setRoles(Collections.singletonList(properties.getJwt().getClaim().getRole().getAdmin()));
                userRepository.save(admin);
            }
        };
    }

}
