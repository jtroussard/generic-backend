package me.devlife4.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtAuthFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Log request URI
        log.info("!![JwtAuthFilter] Filtering request: {}", request.getRequestURI());

        // Skip public endpoints
        if (request.getRequestURI().matches("^/.*/public/.*$")) {
            log.info("!![JwtAuthFilter] Public endpoint detected, skipping authentication.");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT token
        Optional<String> tokenOpt = jwtUtils.getTokenFromRequest(request);
        if (tokenOpt.isEmpty()) {
            log.warn("!![JwtAuthFilter] Missing JWT token, rejecting request.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication token");
            return;
        }

        String token = tokenOpt.get();
        String username;

        try {
            username = jwtUtils.getUsername(token);
            log.info("!![JwtAuthFilter] Extracted username from token: {}", username);
        } catch (Exception e) {
            log.error("!![JwtAuthFilter] Invalid JWT token: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication token");
            return;
        }

        // Check if authentication is already set
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            log.info("!![JwtAuthFilter] Authentication already exists for: {}, skipping.", username);
            filterChain.doFilter(request, response);
            return;
        }

        // Load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            log.warn("!![JwtAuthFilter] User not found: {}", username);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "User not authorized");
            return;
        }

        // Extract roles from JWT
        Set<GrantedAuthority> authorities = jwtUtils.getRoles(token).stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toSet());

        log.info("!![JwtAuthFilter] Extracted roles from JWT: {}", authorities);

        // Set authentication in SecurityContext
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("!![JwtAuthFilter] Set authentication: {} with authorities: {}", username, authorities);

        // Log authorities in SecurityContext
        log.info("!![JwtAuthFilter] SecurityContext authorities at this point: {}",
                SecurityContextHolder.getContext().getAuthentication().getAuthorities());

        filterChain.doFilter(request, response);
    }
}
