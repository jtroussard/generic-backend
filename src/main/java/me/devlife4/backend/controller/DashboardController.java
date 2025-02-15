package me.devlife4.backend.controller;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/dashboard")
public class DashboardController {

    @GetMapping("/admin")
    public ResponseEntity<String> adminDashboard() {
        log.info("!![DashboardController] Admin dashboard accessed");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            log.info("!![DashboardController] Authenticated user: {} with roles: {}", userDetails.getUsername(), userDetails.getAuthorities());
        } else {
            log.warn("!![DashboardController] No authenticated user found in SecurityContext");
        }

        return ResponseEntity.ok("Welcome, Admin!");
    }

    @GetMapping("/user")
    public ResponseEntity<String> userDashboard() {
        log.info("!![DashboardController] User dashboard accessed");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            log.info("!![DashboardController] Authenticated user: {} with roles: {}", userDetails.getUsername(), userDetails.getAuthorities());
        } else {
            log.warn("!![DashboardController] No authenticated user found in SecurityContext");
        }

        return ResponseEntity.ok("Welcome, User!");
    }
}
