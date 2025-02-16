package me.devlife4.backend.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import me.devlife4.backend.enums.RoleTypes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.yml")
@ExtendWith(org.springframework.test.context.junit.jupiter.SpringExtension.class)
public class JwtUtilsTest {

    @Autowired
    private JwtUtils jwtUtils;

    @Value("${spring.security.jwt.secret}")
    private String keySecret;

    @Value("${spring.security.jwt.expiration}")
    private long expirationMs;

    @Test
    void generateTokenShouldReturnToken() {
        String username = "testuser";
        Set<RoleTypes> roles = Set.of(RoleTypes.ROLE_USER);

        String token = jwtUtils.generateToken(username, roles);

        assertNotNull(token);
    }

    @Test
    void getUsernameShouldReturnUsername() {
        String username = "testuser";
        Set<RoleTypes> roles = Set.of(RoleTypes.ROLE_USER);

        String token = jwtUtils.generateToken(username, roles);
        String resolvedUsername = jwtUtils.getUsername(token);

        assertEquals(username, resolvedUsername);
    }

    @Test
    void getUsernameShouldThrowExceptionForExpiredToken() {
        String username = "testuser";
        Set<RoleTypes> roles = Set.of(RoleTypes.ROLE_USER);

        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiration = Date.from(now.minus(Duration.ofMinutes(1)));

        // Duplicate the signing key creation logic here
        String secret = "test_secret_key_that_is_long_enough";
        SecretKey signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));


        String expiredToken = Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList()))
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(RuntimeException.class, () -> jwtUtils.getUsername(expiredToken));
    }

    @Test
    void getUsernameShouldThrowExceptionForInvalidToken() {
        String invalidToken = "this_is_an_invalid_token";

        assertThrows(RuntimeException.class, () -> jwtUtils.getUsername(invalidToken), "Invalid token"); // Check message
    }

    @Test
    void getRolesShouldReturnRoles() {
        String username = "testuser";
        Set<RoleTypes> roles = Set.of(RoleTypes.ROLE_USER, RoleTypes.ROLE_ADMIN);

        SecretKey signingKey = Keys.hmacShaKeyFor(keySecret.getBytes(StandardCharsets.UTF_8));

        String token = Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        Set<RoleTypes> resolvedRoles = jwtUtils.getRoles(token);

        assertEquals(roles, resolvedRoles);
    }

    @Test
    void getRolesShouldReturnEmptySetWhenNoRolesClaim() {
        String username = "testuser";

        SecretKey signingKey = Keys.hmacShaKeyFor(keySecret.getBytes(StandardCharsets.UTF_8));

        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        Set<RoleTypes> resolvedRoles = jwtUtils.getRoles(token);

        assertTrue(resolvedRoles.isEmpty());
    }


    @Test
    void getRolesShouldThrowExceptionForExpiredToken() {
        String username = "testuser";
        Set<RoleTypes> roles = Set.of(RoleTypes.ROLE_USER);

        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiration = Date.from(now.minus(Duration.ofMinutes(1)));

        SecretKey signingKey = Keys.hmacShaKeyFor(keySecret.getBytes(StandardCharsets.UTF_8));

        String expiredToken = Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList()))
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
        String expectedMessage = "Token has expired";

        RuntimeException thrown = assertThrows(RuntimeException.class, () -> jwtUtils.getRoles(expiredToken));
        assertEquals(expectedMessage, thrown.getMessage());
    }

    @Test
    void getRolesShouldThrowExceptionForInvalidToken() {
        String invalidToken = "this_is_an_invalid_token";
        String expectedMessage = "Invalid token";

        RuntimeException thrown =  assertThrows(RuntimeException.class, () -> jwtUtils.getRoles(invalidToken));
        assertEquals(expectedMessage, thrown.getMessage());
    }


}