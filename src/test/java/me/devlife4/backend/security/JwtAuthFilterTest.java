package me.devlife4.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import me.devlife4.backend.enums.RoleTypes;
import me.devlife4.backend.repo.UserRepo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private CustomUserDetailsService customUserDetailsService;

    @InjectMocks
    private JwtAuthFilter jwtAuthFilter;

    @Mock
    private UserRepo userRepo;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @Test
    void shouldRejectRequestWhenNoTokenIsPresent() throws ServletException, IOException {
        when(jwtUtils.getTokenFromRequest(request)).thenReturn(Optional.empty());

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void shouldRejectRequestWhenTokenIsInvalid() throws ServletException, IOException {
        when(jwtUtils.getTokenFromRequest(request)).thenReturn(Optional.of("invalid_token"));
        when(jwtUtils.getUsername("invalid_token")).thenThrow(new RuntimeException("Invalid token"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void shouldAuthenticateRequestWhenTokenIsValid() throws ServletException, IOException {
        when(jwtUtils.getTokenFromRequest(request)).thenReturn(Optional.of("valid_token"));
        when(jwtUtils.getUsername("valid_token")).thenReturn("testUser");
        UserDetails userDetails = User.withUsername("testUser").password("password").authorities("ROLE_USER").build();
        when(customUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);
        when(jwtUtils.getRoles("valid_token")).thenReturn(Set.of(RoleTypes.ROLE_USER));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertNotNull(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void shouldRejectRequestWhenUserNotFound() throws ServletException, IOException {
        when(jwtUtils.getTokenFromRequest(request)).thenReturn(Optional.of("valid_token"));
        when(jwtUtils.getUsername("valid_token")).thenReturn("testUser");
        when(customUserDetailsService.loadUserByUsername("testUser"))
                .thenThrow(new UsernameNotFoundException("User not found"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(customUserDetailsService).loadUserByUsername("testUser");
        assertEquals(403, response.getStatus());  // Expecting Forbidden (403)
    }
}
