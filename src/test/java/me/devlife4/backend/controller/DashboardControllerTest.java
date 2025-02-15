package me.devlife4.backend.controller;

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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.Set;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private UserRepo userRepo;

    @Test
    void shouldAllowAdminAccessToAdminDashboard() throws Exception {
        String username = "adminUser";
        RoleTypes role = RoleTypes.ROLE_ADMIN;
        String validToken = jwtUtils.generateToken(username, Set.of(role));

        User adminUser = new User();
        adminUser.setUsername(username);
        adminUser.setPassword("secure-password");
        adminUser.setRoles(Set.of(role));

        when(userRepo.findByUsername(username)).thenReturn(Optional.of(adminUser));
        when(customUserDetailsService.loadUserByUsername(username)).thenReturn(adminUser);

        mockMvc.perform(get("/dashboard/admin")
                        .cookie(new Cookie("JWT_TOKEN", validToken)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldBlockNonAdminFromAdminDashboard() throws Exception {
        String username = "regularUser";
        RoleTypes role = RoleTypes.ROLE_USER;
        String validToken = jwtUtils.generateToken(username, Set.of(role));

        User regularUser = new User();
        regularUser.setUsername(username);
        regularUser.setPassword("secure-password");
        regularUser.setRoles(Set.of(role));

        when(userRepo.findByUsername(username)).thenReturn(Optional.of(regularUser));
        when(customUserDetailsService.loadUserByUsername(username)).thenReturn(regularUser);

        mockMvc.perform(get("/dashboard/admin")
                        .cookie(new Cookie("JWT_TOKEN", validToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldAllowUserAccessToUserDashboard() throws Exception {
        String username = "regularUser";
        RoleTypes role = RoleTypes.ROLE_USER;
        String validToken = jwtUtils.generateToken(username, Set.of(role));

        User regularUser = new User();
        regularUser.setUsername(username);
        regularUser.setPassword("secure-password");
        regularUser.setRoles(Set.of(role));

        when(userRepo.findByUsername(username)).thenReturn(Optional.of(regularUser));
        when(customUserDetailsService.loadUserByUsername(username)).thenReturn(regularUser);

        mockMvc.perform(get("/dashboard/user")
                        .cookie(new Cookie("JWT_TOKEN", validToken)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldBlockUnauthenticatedUsersFromAccessingDashboards() throws Exception {
        mockMvc.perform(get("/dashboard/admin"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/dashboard/user"))
                .andExpect(status().isUnauthorized());
    }
}
