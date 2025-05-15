package br.app.pdz.api.service.auth;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.service.user.UserDetailsImpl;
import br.app.pdz.api.util.JwtUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@Log4j2
public class AuthService {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserDetailsService userDetailsService;

    public AuthService(JwtUtil jwtUtil, AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository, @Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userDetailsService = userDetailsService;
    }

    public ResponseEntity<String> verifyExistence(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            log.error("Username already exists: {}", username);
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(email)) {
            log.error("Email already exists: {}", email);
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        return ResponseEntity.ok("User and email are available");
    }

    public ResponseEntity<String> signUp(SignUpRequest signUpRequest) {
        String encodedPassword = passwordEncoder.encode(signUpRequest.password());

        Set<Role> roles = new HashSet<>();
        Optional<Role> userRole = roleRepository.findByName(EnumRole.ROLE_USER);

        if (userRole.isEmpty())
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: Role not found!");

        roles.add(userRole.get());

        User user = new User();
        user.setUsername(signUpRequest.username());
        user.setEmail(signUpRequest.email());
        user.setPassword(encodedPassword);
        user.setRoles(roles);
        userRepository.save(user);

        log.info("User registered successfully: {}", user.getUsername());
        return ResponseEntity.ok("User registered successfully!");
    }

    public JwtResponse signIn(SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.username(),
                        signInRequest.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("User authenticated successfully: {}", signInRequest.username());
        return jwtUtil.createJwtResponse((UserDetailsImpl) authentication.getPrincipal());
    }

    public ResponseEntity<?> handleOAuth2SignIn(DefaultOAuth2User oAuth2User) {
        log.info("Handling OAuth2 sign-in for user: {}", oAuth2User);
        try {
            User user = userRepository.findByDiscordId(oAuth2User.getAttribute("id"))
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setDiscordId(oAuth2User.getAttribute("id"));
                        newUser.setUsername(oAuth2User.getAttribute("username"));
                        newUser.setEmail(oAuth2User.getAttribute("email"));

                        Set<Role> roles = new HashSet<>();
                        roles.add(roleRepository.findByName(EnumRole.ROLE_USER).orElse(null));
                        newUser.setRoles(roles);

                        log.info("Created new user from oAuth2 login: {}", newUser.getUsername());

                        return newUser;
                    });

            user.setProfilePictureName(oAuth2User.getAttribute("avatar"));
            userRepository.save(user);

            log.info("User signed in with oAuth2: {}", user.getUsername());
            return ResponseEntity.ok(jwtUtil.createJwtResponse((UserDetailsImpl) userDetailsService.loadUserByUsername(user.getUsername())));
        } catch (Exception e) {
            log.error("Error in oAuth2 login handler", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing oAuth2 login: " + e.getMessage());
        }
    }

}
