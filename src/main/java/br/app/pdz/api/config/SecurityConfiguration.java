package br.app.pdz.api.config;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.filter.AuthTokenFilter;
import br.app.pdz.api.filter.AuthEntryPointJwt;
import br.app.pdz.api.service.AuthService;
import br.app.pdz.api.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@Log4j2
@EnableWebSecurity
@EnableMethodSecurity()
public class SecurityConfiguration {
    private final AuthEntryPointJwt authEntryPoint;
    private final AuthTokenFilter authTokenFilter;
    private final UserService userService;

    @Value("${pdz.frontend.origin}")
    private String frontend;

    public SecurityConfiguration(AuthEntryPointJwt authEntryPoint, AuthTokenFilter authTokenFilter, UserService userService) {
        this.authEntryPoint = authEntryPoint;
        this.authTokenFilter = authTokenFilter;
        this.userService = userService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Primary
    public AuthenticationManagerBuilder configureAuthenticationManagerBuilder(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthService authService) throws Exception {
        http
                .cors(cors -> cors
                        .configurationSource(request -> {
                            var corsConfiguration = new org.springframework.web.cors.CorsConfiguration();
                            corsConfiguration.setAllowedOrigins(List.of(frontend));
                            corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                            corsConfiguration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                            corsConfiguration.setAllowCredentials(true);
                            return corsConfiguration;
                        })
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/pdz-api/auth/**", "/pdz-api/oauth2/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .successHandler((request, response, authentication) -> {
                            request.getSession().setAttribute("user", authentication.getPrincipal());

                            DefaultOAuth2User oAuth2User = (DefaultOAuth2User) request.getSession().getAttribute("user");
                            JwtResponse jwtResponse = authService.handleOAuth2SignIn(oAuth2User, request, response);

                            String callbackUrl = (String) request.getSession().getAttribute("oauth_callback");

                            log.info(callbackUrl);

                            request.getSession().removeAttribute("oauth_callback");

                            if (callbackUrl == null || callbackUrl.isEmpty()) {
                                callbackUrl = frontend + "/auth/success";
                            }

                            String separator = callbackUrl.contains("?") ? "&" : "?";
                            callbackUrl += separator + "token=" + jwtResponse.token() +
                                    "&username=" + jwtResponse.username() +
                                    "&roles=" + jwtResponse.roles();

                            response.sendRedirect(callbackUrl);
                        })
                        .failureHandler((request, response, exception) -> {
                            String callbackUrl = (String) request.getSession().getAttribute("oauth_callback");
                            request.getSession().removeAttribute("oauth_callback");

                            if (callbackUrl == null || callbackUrl.isEmpty()) {
                                callbackUrl = frontend + "/auth/failure";
                            }

                            response.sendRedirect(callbackUrl);
                        })
                )
                .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
