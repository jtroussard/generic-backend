package me.devlife4.backend.config;

import lombok.extern.slf4j.Slf4j;
import me.devlife4.backend.security.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        log.debug("!![SecurityConfig] AuthenticationManager initialized with DaoAuthenticationProvider");

        return new ProviderManager(authProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.debug("!![SecurityConfig] Configuring SecurityFilterChain");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    log.debug("!![SecurityConfig] Configuring authorization rules");

                    // Public Endpoints (Open to all)
                    log.debug("!![SecurityConfig] Public endpoints: /*/public/** → permitAll()");
                    auth.requestMatchers("/*/public/**").permitAll();

                    // Private Endpoints (Require authentication)
                    log.debug("!![SecurityConfig] Private endpoints: /*/private/** → authenticated()");
                    auth.requestMatchers("/*/private/**").authenticated();

                    // Role-Based Endpoints (Require specific roles)
                    log.debug("!![SecurityConfig] Role-based endpoint: /admin/** → hasAuthority(\"ADMIN\") (Spring auto-prepends ROLE_)");
                    auth.requestMatchers("/*/admin").hasAuthority("ROLE_ADMIN");

                    log.debug("!![SecurityConfig] Role-based endpoint: /user/** → hasAuthority(\"USER\") (Spring auto-prepends ROLE_)");
                    auth.requestMatchers("/*/user/**").hasAuthority("ROLE_USER");
                })
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}