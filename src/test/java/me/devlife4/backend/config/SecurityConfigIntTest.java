package me.devlife4.backend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.CustomUserDetailsService;
import me.devlife4.backend.security.JwtUtils;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.Set;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigIntTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private UserRepo userRepo;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void shouldAllowAccessToLoginAndRegisterEndpoints() throws Exception {
        mockMvc.perform(get("/auth/public/login"))
                .andExpect(status().isMethodNotAllowed());

        mockMvc.perform(get("/auth/public/register"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void shouldBlockAccessToPrivateEndpointsWhenNotAuthenticated() throws Exception {
        mockMvc.perform(get("/auth/private/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldBlockAccessToPrivateEndpointsWithInvalidToken() throws Exception {
        mockMvc.perform(get("/auth/private/me")
                        .cookie(new Cookie("JWT_TOKEN", "invalidToken")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldBlockAccessToPrivateEndpointsWithMissingToken() throws Exception {
        mockMvc.perform(get("/auth/private/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldAllowAccessToProtectedEndpointsWhenAuthenticated() throws Exception {
        String username = "testUser";
        RoleTypes role = RoleTypes.ROLE_USER;
        String validToken = jwtUtils.generateToken(username, Set.of(role));

        User user = new User();
        user.setUsername(username);
        user.setPassword("good-password");
        user.setRoles(Set.of(RoleTypes.ROLE_USER));

        // Mock UserRepo and CustomUserDetailsService
        when(userRepo.findByUsername(username)).thenReturn(Optional.of(user));
        when(customUserDetailsService.loadUserByUsername(username)).thenReturn(user);

        mockMvc.perform(get("/auth/private/me")
                        .cookie(new Cookie("JWT_TOKEN", validToken)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturnBadRequestToPublicEndpointsWithoutProperRequest() throws Exception {
        mockMvc.perform(post("/auth/public/login"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldAllowLoginWithValidCredentials() throws Exception {
        String username = "testUser";
        String rawPassword = "good-password";
        String hashedPassword = new BCryptPasswordEncoder().encode(rawPassword);
        RoleTypes role = RoleTypes.ROLE_USER;
        String expectedToken = jwtUtils.generateToken(username, Set.of(role));

        User mockUser = new User();
        mockUser.setUsername(username);
        mockUser.setPassword(hashedPassword);
        mockUser.setRoles(Set.of(role));

        when(userRepo.findByUsername(username)).thenReturn(Optional.of(mockUser));

        AuthRequest loginRequest = new AuthRequest(username, rawPassword);
        String requestBody = objectMapper.writeValueAsString(loginRequest);

        mockMvc.perform(post("/auth/public/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(cookie().exists("JWT_TOKEN")); // Ensures the token cookie is set
    }

    @Test
    void shouldReturn404ToPublicEndpointsThatAreNotDefinedInTheController() throws Exception {
        mockMvc.perform(get("/auth/public/tuna"))
                .andExpect(status().isNotFound());
    }

}
