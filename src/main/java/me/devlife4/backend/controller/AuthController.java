package me.devlife4.backend.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.dto.response.AuthResponse;
import me.devlife4.backend.dto.request.RegisterRequest;
import me.devlife4.backend.dto.response.UserResponse;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UserRepo userRepo;
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthController(UserRepo userRepo, JwtUtils jwtUtils, BCryptPasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/public/register")
    public AuthResponse register(@RequestBody RegisterRequest request, HttpServletResponse response) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepo.save(user);

        String token = jwtUtils.generateToken(user.getUsername(), Set.of(RoleTypes.ROLE_USER));
        jwtUtils.setTokenCookie(response, token); // CRITICAL REQUIREMENT

        return new AuthResponse(token);
    }

    @PostMapping("/public/login")
    public AuthResponse login(@RequestBody AuthRequest request, HttpServletResponse response) {
        Optional<User> userOpt = userRepo.findByUsername(request.getUsername());

        if (userOpt.isPresent() && passwordEncoder.matches(request.getPassword(), userOpt.get().getPassword())) {
            String token = jwtUtils.generateToken(userOpt.get().getUsername(), userOpt.get().getRoles());
            jwtUtils.setTokenCookie(response, token);
            return new AuthResponse(token);
        }

        throw new RuntimeException("Invalid credentials");
    }

// TODO Let's just get basic authentication workflow going first then enhance with refresh functionality
//
//    @PostMapping("/public/refresh")
//    public AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
//        Optional<String> tokenOpt = jwtUtils.getTokenFromRequest(request);
//        if (tokenOpt.isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No token provided");
//        }
//
//        String token = tokenOpt.get();
//        try {
//            // Validate the token and extract the username
//            String username = jwtUtils.getUsername(token);
//            Set<RoleTypes> roles = jwtUtils.getRoles(token);
//
//            // Generate a new access token
//            String newToken = jwtUtils.generateToken(username, roles);
//            jwtUtils.setTokenCookie(response, newToken);
//
//            return new AuthResponse(newToken);
//        } catch (RuntimeException e) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
//        }
//    }

    @PostMapping("/private/logout")
    public void logout(HttpServletResponse response) {
        log.info("[AUTH] User logging out.");
        jwtUtils.clearTokenCookie(response);
    }

    @GetMapping("/private/me")
    public UserResponse getAuthenticatedUser(@CookieValue(name = "JWT_TOKEN", required = false) String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No token provided");
        }

        try {
            String username = jwtUtils.getUsername(token);
            return userRepo.findByUsername(username)
                    .map(UserResponse::new)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage());
        }
    }

}
