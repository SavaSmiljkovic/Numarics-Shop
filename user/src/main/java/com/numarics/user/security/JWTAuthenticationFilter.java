package com.numarics.user.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.numarics.user.model.User;
import com.numarics.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final Properties properties;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, Properties properties) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.properties = properties;
        setFilterProcessesUrl(properties.getUrl().getLogin());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        try {
            User user = new ObjectMapper().readValue(req.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(),
                                                                                                user.getPassword());
            return authenticationManager.authenticate(token);
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid username or password. Message: " + e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) {
        String username = auth.getName();

        if (!userRepository.existsByUsername(username)) {
            return;
        }

        List<String> roles = auth.getAuthorities().stream()
                                 .map(GrantedAuthority::getAuthority)
                                 .collect(Collectors.toList());

        String jwtToken = JWT.create()
                             .withSubject(username)
                             .withIssuedAt(new Date())
                             .withExpiresAt(Date.from(Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(1, ChronoUnit.HOURS)))
                             .withClaim(properties.getJwt().getClaim().getRoleTitle(), roles)
                             .sign(Algorithm.HMAC256(properties.getJwt().getSecret()));

        res.addHeader(properties.getJwt().getHeader(), properties.getJwt().getPrefix() + " " + jwtToken);
    }

}
