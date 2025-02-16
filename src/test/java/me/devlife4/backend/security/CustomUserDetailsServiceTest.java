package me.devlife4.backend.security;

import me.devlife4.backend.entity.User;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
        import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomUserDetailsServiceTest {

    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    @Mock
    private UserRepo userRepo;

    @Test
    void loadUserByUsernameShouldReturnUserDetails() {
        String username = "testuser";
        User user = new User();
        user.setUsername(username);
        user.setPassword("password");
        user.setRoles(Set.of(RoleTypes.ROLE_USER));

        when(userRepo.findByUsername(username)).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        Set<RoleTypes> expectedRoles = Set.of(RoleTypes.ROLE_USER);

        Set<RoleTypes> actualRoles = userDetails.getAuthorities().stream()
                .map(authority -> RoleTypes.valueOf(authority.getAuthority())) // Extract enum value
                .collect(Collectors.toSet());

        assertEquals(expectedRoles, actualRoles);
        assertEquals(username, userDetails.getUsername());
        assertEquals("password", userDetails.getPassword());

        verify(userRepo).findByUsername(username);
    }

    @Test
    void loadUserByUsernameShouldThrowExceptionWhenUserNotFound() {
        String username = "nonexistentuser";

        when(userRepo.findByUsername(username)).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> userDetailsService.loadUserByUsername(username));

        verify(userRepo).findByUsername(username);
    }


    @Test
    void loadUserByUsernameShouldThrowExceptionWithMessageWhenUserNotFound() {
        String username = "nonexistentuser";

        when(userRepo.findByUsername(username)).thenReturn(Optional.empty());
        String expectedMessage = "User not found: " + username;

        UsernameNotFoundException thrown = assertThrows(UsernameNotFoundException.class, () -> userDetailsService.loadUserByUsername(username));
        assertEquals(expectedMessage, thrown.getMessage());

        verify(userRepo).findByUsername(username);
    }
}