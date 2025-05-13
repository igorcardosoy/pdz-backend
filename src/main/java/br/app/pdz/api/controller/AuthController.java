package br.app.pdz.api.controller;

import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.service.UserDetailsImpl;
import br.app.pdz.api.service.UserDetailsServiceImpl;
import br.app.pdz.api.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                            UserDetailsServiceImpl userDetailsService,
                          JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.username(),
                        signInRequest.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return ResponseEntity.ok(jwtUtil.createJwtResponse((UserDetailsImpl) authentication.getPrincipal()));
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.username())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.email())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

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

        return ResponseEntity.ok("User registered successfully!");
    }

    @GetMapping("/discord/success")
    public ResponseEntity<?> handleDiscordLogin(HttpServletRequest request, HttpServletResponse response) {
        try {
            DefaultOAuth2User discordUser = (DefaultOAuth2User) request.getSession().getAttribute("user");
            request.getSession().invalidate();

            if (discordUser == null) {
                response.sendRedirect("/auth/discord/failure");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Discord authentication failed.");
            }

            User user = userRepository.findByDiscordId(discordUser.getAttribute("id"))
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setDiscordId(discordUser.getAttribute("id"));
                        newUser.setUsername(discordUser.getAttribute("username"));
                        newUser.setEmail(discordUser.getAttribute("email"));

                        Set<Role> roles = new HashSet<>();
                        roles.add(roleRepository.findByName(EnumRole.ROLE_USER).orElse(null));
                        newUser.setRoles(roles);

                        User savedUser = userRepository.save(newUser);
                        log.info("Created new user from Discord login: {}", savedUser.getUsername());

                        return savedUser;
                    });


            return ResponseEntity.ok(jwtUtil.createJwtResponse((UserDetailsImpl) userDetailsService.loadUserByUsername(user.getUsername())));
        } catch (Exception e) {
            log.error("Error in Discord login handler", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing Discord login: " + e.getMessage());
        }
    }

    @GetMapping("/discord/failure")
    public ResponseEntity<String> handleDiscordFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Discord authentication failed.");
    }
}
