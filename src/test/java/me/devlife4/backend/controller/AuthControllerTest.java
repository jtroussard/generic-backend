package me.devlife4.backend.controller;

import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.dto.request.RegisterRequest;
import me.devlife4.backend.dto.response.AuthResponse;
import me.devlife4.backend.dto.response.UserResponse;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    @Mock
    private UserRepo userRepo;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void loginShouldReturnAuthResponseWhenCredentialsAreValid() {
        // Arrange
        AuthRequest request = new AuthRequest("testUser", "password");
        User user = new User();
        user.setUsername("testUser");
        user.setPassword("$2a$10$hashedpassword");
        user.setRoles(Set.of(RoleTypes.ROLE_USER));

        when(userRepo.findByUsername(user.getUsername())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password", "$2a$10$hashedpassword")).thenReturn(true);
        when(jwtUtils.generateToken(user.getUsername(), user.getRoles())).thenReturn("mocked-jwt-token");

        // Act
        AuthResponse response = authController.login(request, this.response);

        // Assert
        assertNotNull(response);
        assertEquals("mocked-jwt-token", response.getToken());
        verify(jwtUtils).setTokenCookie(this.response, "mocked-jwt-token");
    }

    @Test
    void loginShouldThrowExceptionWhenCredentialsAreInvalid() {
        // Arrange
        AuthRequest request = new AuthRequest("testUser", "wrongPassword");
        User user = new User();
        user.setUsername("testUser");
        user.setPassword("$2a$10$hashedpassword");

        when(userRepo.findByUsername("testUser")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPassword", "$2a$10$hashedpassword")).thenReturn(false);

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () ->
                authController.login(request, response)
        );

        assertEquals("Invalid credentials", exception.getMessage());
        verify(jwtUtils, never()).generateToken(anyString(), anySet());
        verify(jwtUtils, never()).setTokenCookie(any(), anyString());
    }

    @Test
    void loginShouldThrowExceptionWhenUserDoesNotExist() {
        // Arrange
        AuthRequest request = new AuthRequest("nonExistentUser", "somePassword");

        when(userRepo.findByUsername("nonExistentUser")).thenReturn(Optional.empty());

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () ->
                authController.login(request, response)
        );

        assertEquals("Invalid credentials", exception.getMessage());
        verify(jwtUtils, never()).generateToken(anyString(), anySet());
        verify(jwtUtils, never()).setTokenCookie(any(), anyString());
    }

    @Test
    void registerShouldCreateUserAndReturnToken() {
        // Arrange
        RegisterRequest request = new RegisterRequest("newUser", "securePassword");
        User newUser = new User();
        newUser.setUsername("newUser");
        newUser.setPassword("$2a$10$hashedpassword");
        newUser.setRoles(Set.of(RoleTypes.ROLE_USER));

        when(userRepo.save(any(User.class))).thenReturn(newUser);
        when(jwtUtils.generateToken(newUser.getUsername(), newUser.getRoles())).thenReturn("mocked-jwt-token");

        // Act
        AuthResponse response = authController.register(request, this.response);

        // Assert
        assertNotNull(response);
        assertEquals("mocked-jwt-token", response.getToken());
        verify(userRepo).save(any(User.class));
        verify(jwtUtils).setTokenCookie(this.response, "mocked-jwt-token");
    }

    @Test
    void meShouldReturnUserResponseWhenTokenIsValid() {
        // Arrange
        String token = "mocked-jwt-token";
        String username = "testUser";
        User user = new User();
        user.setUsername(username);

        when(jwtUtils.getUsername(token)).thenReturn(username);
        when(userRepo.findByUsername(username)).thenReturn(Optional.of(user));

        // Act
        UserResponse response = authController.getAuthenticatedUser(token);

        // Assert
        assertNotNull(response);
        assertEquals(username, response.getUsername());
    }

    @Test
    void meShouldThrowExceptionWhenTokenIsInvalid() {
        // Arrange
        String invalidToken = "invalid-token";
        when(jwtUtils.getUsername(invalidToken)).thenThrow(new RuntimeException("Invalid token"));

        // Act & Assert
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                authController.getAuthenticatedUser(invalidToken)
        );

        assertEquals("401 UNAUTHORIZED \"Invalid token\"", exception.getMessage());
    }

    @Test
    void meShouldThrowExceptionWhenUserNotFound() {
        // Arrange
        String token = "mocked-jwt-token";
        String username = "nonExistentUser";

        when(jwtUtils.getUsername(token)).thenReturn(username);
        when(userRepo.findByUsername(username)).thenReturn(Optional.empty());

        // Act & Assert
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                authController.getAuthenticatedUser(token)
        );

        assertEquals("401 UNAUTHORIZED \"User not found\"", exception.getReason());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    void logoutShouldClearTokenCookie() {
        // Act
        authController.logout(response);

        // Assert
        verify(jwtUtils).clearTokenCookie(response);
    }
}
