package me.devlife4.backend.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import me.devlife4.backend.enums.RoleTypes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtils {

    @Value("${spring.security.jwt.secret}")
    private String secret;

    @Value("${spring.security.jwt.expiration}")
    private long expirationMs;

    private SecretKey getSigningKey() {
        log.info("!![JwtUtils] Generating signing key using secret.");
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String username, Set<RoleTypes> roles) {
        log.info("!![JwtUtils] Generating token for username: {}, roles: {}", username, roles);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Enum::name).collect(Collectors.toList())) // Store roles
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsername(String token) {
        log.info("!![JwtUtils] Extracting username from token: {}", token);
        try {
            String username = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
            log.info("!![JwtUtils] Successfully extracted username: {}", username);
            return username;
        } catch (ExpiredJwtException e) {
            log.error("!![JwtUtils] Token has expired: {}", token);
            throw new RuntimeException("Token has expired");
        } catch (JwtException e) {
            log.error("!![JwtUtils] Invalid token: {}", token);
            throw new RuntimeException("Invalid token");
        }
    }

    public Set<RoleTypes> getRoles(String token) {
        log.info("!![JwtUtils] Getting roles from token: {}", token);
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            List<String> roles = claims.get("roles", List.class);
            if (roles == null) {
                log.info("!![JwtUtils] No roles found in token.");
                return Set.of();
            }
            Set<RoleTypes> roleSet = roles.stream().map(RoleTypes::valueOf).collect(Collectors.toSet());
            log.info("!![JwtUtils] Extracted roles: {}", roleSet);
            return roleSet;
        } catch (ExpiredJwtException e) {
            log.error("!![JwtUtils] Token has expired: {}", token);
            throw new RuntimeException("Token has expired");
        } catch (JwtException e) {
            log.error("!![JwtUtils] Invalid token: {}", token);
            throw new RuntimeException("Invalid token");
        }
    }

    public void setTokenCookie(HttpServletResponse response, String token) {
        log.info("!![JwtUtils] Setting token cookie with token: {}", token);
        try {
            Cookie cookie = new Cookie("JWT_TOKEN", token);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
            log.info("!![JwtUtils] Token cookie set successfully.");
        } catch (Exception e) {
            log.error("!![JwtUtils] Exception in setTokenCookie: {}", e.getMessage(), e);
            throw e; // Re-throw to fail fast
        }
    }

    public Optional<String> getTokenFromRequest(HttpServletRequest request) {
        log.info("!![JwtUtils] Extracting token from request.");
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("JWT_TOKEN".equals(cookie.getName())) {
                    log.info("!![JwtUtils] Found token in cookie: {}", cookie.getValue());
                    return Optional.of(cookie.getValue());
                }
            }
        }
        log.info("!![JwtUtils] No token found in request.");
        return Optional.empty();
    }

    public void clearTokenCookie(HttpServletResponse response) {
        log.info("!![JwtUtils] Clearing token cookie.");
        Cookie cookie = new Cookie("JWT_TOKEN", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Expire the cookie immediately
        response.addCookie(cookie);
        log.info("!![JwtUtils] Token cookie cleared successfully.");
    }
}