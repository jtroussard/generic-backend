package me.devlife4.backend.security;

import lombok.extern.slf4j.Slf4j;
import me.devlife4.backend.entity.User;
import me.devlife4.backend.repo.UserRepo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepo userRepo;

    public CustomUserDetailsService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("!![CustomUserDetailsService] Loading user by username: {}", username);

        Optional<User> userOpt = userRepo.findByUsername(username);
        if (userOpt.isEmpty()) {
            log.warn("!![CustomUserDetailsService] User not found: {}", username);
            throw new UsernameNotFoundException("User not found: " + username);
        }

        User user = userOpt.get();
        log.debug("!![CustomUserDetailsService] Found user: {} with roles: {}", user.getUsername(), user.getAuthorities());

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
    }
}
