package me.devlife4.backend.controller;

import jakarta.servlet.http.HttpServletResponse;
import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.dto.response.AuthResponse;
import me.devlife4.backend.dto.request.RegisterRequest;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.JwtUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

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

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepo.save(user);

        String token = jwtUtils.generateToken(user.getUsername());
        return new AuthResponse(token);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request, HttpServletResponse response) {
        Optional<User> userOpt = userRepo.findByUsername(request.getUsername());

        if (userOpt.isPresent() && passwordEncoder.matches(request.getPassword(), userOpt.get().getPassword())) {
            String token = jwtUtils.generateToken(userOpt.get().getUsername());
            jwtUtils.setTokenCookie(response, token);
            return new AuthResponse(token);
        }

        throw new RuntimeException("Invalid credentials");
    }
}
