package me.devlife4.backend.controller;

import jakarta.servlet.http.HttpServletResponse;
import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.dto.response.AuthResponse;
import me.devlife4.backend.dto.request.RegisterRequest;
import me.devlife4.backend.dto.response.UserResponse;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

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

        String token = jwtUtils.generateToken(user.getUsername());
        jwtUtils.setTokenCookie(response, token); // CRITICAL REQUIREMENT

        return new AuthResponse(token);
    }

    @PostMapping("/public/login")
    public AuthResponse login(@RequestBody AuthRequest request, HttpServletResponse response) {
        Optional<User> userOpt = userRepo.findByUsername(request.getUsername());

        if (userOpt.isPresent() && passwordEncoder.matches(request.getPassword(), userOpt.get().getPassword())) {
            String token = jwtUtils.generateToken(userOpt.get().getUsername());
            jwtUtils.setTokenCookie(response, token);
            return new AuthResponse(token);
        }

        throw new RuntimeException("Invalid credentials");
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

    @PostMapping("/private/logout")
    public void logout(HttpServletResponse response) {
        jwtUtils.clearTokenCookie(response);
    }
}
