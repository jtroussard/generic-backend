package me.devlife4.backend.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import me.devlife4.backend.dto.request.AuthRequest;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import me.devlife4.backend.security.CustomUserDetailsService;
import me.devlife4.backend.security.JwtUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerIntTest {

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

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Test
    void shouldLogoutUserAndClearTokenCookie() throws Exception {
        // Login to get a valid token
        String username = "testUser";
        String password = "testPassword";
        String encodedPassword = passwordEncoder.encode(password);

        log.info("why does my user not have an encoded password??? {}", encodedPassword);
        log.info("live encoding {}", passwordEncoder.encode("FUCK THIS"));

        User user = new User();
        user.setUsername(username);
        user.setPassword(encodedPassword);
        user.setRoles(Set.of(RoleTypes.ROLE_USER));
        // TODO set up H2 for real integration testing
//        userRepo.save(user);

        // Mocking UserRepo
        when(userRepo.findByUsername(Mockito.anyString())).thenReturn(Optional.of(user));

// Mocking CustomUserDetailsService to return a valid UserDetails object
        when(customUserDetailsService.loadUserByUsername(Mockito.anyString()))
                .thenAnswer(invocation -> {
                    String requestedUsername = invocation.getArgument(0);
                    log.info("Mocked loadUserByUsername for {}", requestedUsername);
                    return org.springframework.security.core.userdetails.User
                            .builder()
                            .username(requestedUsername)
                            .password(encodedPassword)
                            .authorities("ROLE_USER") // Ensure role is set
                            .build();
                });


        AuthRequest authRequest = new AuthRequest(username, password);
        // Perform login request
        MvcResult loginResult = mockMvc.perform(post("/auth/public/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AuthRequest(username, password))))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("JWT_TOKEN")) // Verify cookie is set
                .andDo(print()) // Debugging: Print request and response
                .andReturn();

        // Extract the JWT token cookie from the login response
        Cookie jwtCookie = loginResult.getResponse().getCookie("JWT_TOKEN");
        assertNotNull(jwtCookie, "JWT token cookie should not be null");

        // Perform logout request with the JWT token cookie
        mockMvc.perform(post("/auth/private/logout")
                        .cookie(jwtCookie)) // Include the JWT token cookie
                .andExpect(status().isOk())
                .andExpect(cookie().exists("JWT_TOKEN")) // Verify cookie is still present
                .andExpect(cookie().maxAge("JWT_TOKEN", 0)) // Verify cookie is expired
                .andDo(print()); // Debugging: Print request and response

        // Verify subsequent requests are unauthorized
        mockMvc.perform(get("/auth/private/me")
                        .cookie(new Cookie("JWT_TOKEN", "invalidToken")))
                .andExpect(status().isUnauthorized());
    }
}
