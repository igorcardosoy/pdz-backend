package br.app.pdz.api.controller;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.service.UserDetailsImpl;
import br.app.pdz.api.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
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
        String jwt = jwtUtil.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        JwtResponse response = new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                roles
        );

        return ResponseEntity.ok(response);
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

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public UserDetailsImpl checkUserAccess() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        log.info("username: {}", userDetails.getUsername());

        return userDetails;
    }

    @PostMapping("/discord/success")
    public ResponseEntity<?> handleDiscordLogin(OAuth2AuthenticationToken authentication) {
        String discordId = authentication.getPrincipal().getAttribute("id");
        String email = authentication.getPrincipal().getAttribute("email");
        String username = authentication.getPrincipal().getAttribute("username");

        User user = userRepository.findByDiscordId(discordId)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setDiscordId(discordId);
                    newUser.setEmail(email);
                    newUser.setUsername(username);
                    newUser.setRoles(Set.of(roleRepository.findByName(EnumRole.ROLE_USER).orElseThrow()));
                    return userRepository.save(newUser);
                });

        String jwt = jwtUtil.generateJwtToken(new UsernamePasswordAuthenticationToken(user.getUsername(), null,
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                        .collect(Collectors.toList())));

        return ResponseEntity.ok(new JwtResponse(jwt, user.getId(), user.getUsername(),
                user.getRoles().stream().map(Role::getName).map(Enum::name).collect(Collectors.toList())));
    }

    @GetMapping("/discord/failure")
    public ResponseEntity<String> handleDiscordFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Discord authentication failed.");
    }
}
