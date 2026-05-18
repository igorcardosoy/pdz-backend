package br.app.pdz.api.config;

import br.app.pdz.api.filter.AuthEntryPointJwt;
import br.app.pdz.api.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
@Log4j2
@EnableWebSecurity
@EnableMethodSecurity()
public class SecurityConfiguration {
    private final AuthEntryPointJwt authEntryPoint;
    private final UserService userService;

    @Value("${pdz.frontend.origin}")
    private List<String> frontendOrigins;

    @Value("${pdz.security.logto.issuer-uri}")
    private String issuerUri;

    @Value("${pdz.security.logto.audience}")
    private String audience;

    public SecurityConfiguration(AuthEntryPointJwt authEntryPoint, UserService userService) {
        this.authEntryPoint = authEntryPoint;
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
    public RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(30000);
        factory.setReadTimeout(120000);
        return new RestTemplate(factory);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors
                        .configurationSource(request -> {
                            var corsConfiguration = new org.springframework.web.cors.CorsConfiguration();
                            corsConfiguration.setAllowedOrigins(frontendOrigins);
                            corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                            corsConfiguration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                            corsConfiguration.setAllowCredentials(true);
                            return corsConfiguration;
                        })
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/pdz-api/auth/**", "/oauth2/**", "/login/oauth2/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/pdz-api/mine-codes/accounts").permitAll()
                        .requestMatchers(HttpMethod.POST, "/pdz-api/mine-codes/code-2AF").permitAll()
                        .requestMatchers("/pdz-api/debug/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            log.info("Inicializando JwtDecoder com issuer-uri: {}, audience: {}", issuerUri, audience);
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
            OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuerUri);
            OAuth2TokenValidator<Jwt> audienceValidator = token -> {
                List<String> audiences = token.getAudience();
                log.debug("Token audience: {}, esperado: {}", audiences, audience);
                if (audiences != null && audiences.contains(audience)) {
                    log.debug("Audience válida");
                    return OAuth2TokenValidatorResult.success();
                }

                String errorMsg = "Token does not contain the required audience. Expected: [" + audience + "], got: " + audiences;
                log.warn("Audience inválida: {}", errorMsg);
                OAuth2Error error = new OAuth2Error(
                        "invalid_token",
                        errorMsg,
                        null
                );
                return OAuth2TokenValidatorResult.failure(error);
            };

            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator));
            log.info("JwtDecoder inicializado com sucesso");
            return decoder;
        } catch (Exception e) {
            log.error("Erro ao inicializar JwtDecoder", e);
            throw new RuntimeException("Failed to initialize JwtDecoder", e);
        }
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
        scopesConverter.setAuthorityPrefix("SCOPE_");

        Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter = jwt -> {
            Set<GrantedAuthority> authorities = new HashSet<>(scopesConverter.convert(jwt));

            Object rolesClaim = jwt.getClaims().get("roles");
            if (rolesClaim instanceof Collection<?> rolesCollection) {
                for (Object role : rolesCollection) {
                    if (role != null) {
                        String roleName = role.toString().trim();
                        if (!roleName.isEmpty()) {
                            String normalizedRole = roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName.toUpperCase();
                            authorities.add(new SimpleGrantedAuthority(normalizedRole));
                        }
                    }
                }
            } else if (rolesClaim instanceof String rolesString && !rolesString.isBlank()) {
                for (String role : rolesString.split("[,\\s]+")) {
                    if (!role.isBlank()) {
                        String normalizedRole = role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase();
                        authorities.add(new SimpleGrantedAuthority(normalizedRole));
                    }
                }
            }

            return authorities;
        };

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }

}
