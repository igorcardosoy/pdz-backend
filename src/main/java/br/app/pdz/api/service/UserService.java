package br.app.pdz.api.service;

import br.app.pdz.api.dto.PasswordChangeRequest;
import br.app.pdz.api.dto.ProfilePictureDTO;
import br.app.pdz.api.dto.UserDTO;
import br.app.pdz.api.exception.PasswordException;
import br.app.pdz.api.exception.ProfilePictureException;
import br.app.pdz.api.exception.RoleNotFoundException;
import br.app.pdz.api.model.User;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.exception.UserNotFoundException;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, @Lazy PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDTO loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDTO.build(user);
    }

    public UserDTO getUserDTOSignedIn() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        if (authentication == null || authentication.getPrincipal() == null) {
            throw new UserNotFoundException("Authenticated user not found", HttpStatus.UNAUTHORIZED);
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDTO userDTO) {
            return userDTO;
        }

        if (principal instanceof Jwt jwt) {
            User user = resolveOrCreateUserFromJwt(jwt);
            return UserDTO.build(user);
        }

        throw new UserNotFoundException("Unsupported authentication principal", HttpStatus.UNAUTHORIZED);
    }

    public void changePassword(PasswordChangeRequest passwordChangeRequest) {

        User user = userRepository.findByEmail(passwordChangeRequest.email()).orElseThrow(() -> new UserNotFoundException("User not found with email: " + passwordChangeRequest.email(), HttpStatus.NOT_FOUND));

        if (!passwordEncoder.matches(passwordChangeRequest.oldPassword(), user.getPassword())) {
            throw new PasswordException("Old password is incorrect", HttpStatus.BAD_REQUEST);
        }

        user.setPassword(passwordEncoder.encode(passwordChangeRequest.newPassword()));
        userRepository.save(user);
    }

    public ProfilePictureDTO<?> getProfilePicture(UserDTO userDTO) throws IOException {
        if (userDTO.getDiscordId() != null) {
            String avatarUrl = "https://cdn.discordapp.com/avatars/" + userDTO.getDiscordId() + "/" + userDTO.getProfilePictureName() + ".png";
            return new ProfilePictureDTO<>(
                    avatarUrl,
                    "text/plain",
                    String.valueOf(avatarUrl.length())
            );
        }

        if (userDTO.getProfilePictureName() != null && (userDTO.getProfilePictureName().startsWith("https://") || userDTO.getProfilePictureName().startsWith("http://"))) {
            String avatarUrl = userDTO.getProfilePictureName();
            return new ProfilePictureDTO<>(
                    avatarUrl,
                    "text/plain",
                    String.valueOf(avatarUrl.length())
            );
        }

        if (userDTO.getProfilePictureName() == null)
            throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);


        String uploadDir = "src/main/resources/images/profile_pics/";
        File file = new File(uploadDir + userDTO.getProfilePictureName());

        log.info("Profile picture retrieved for user: {}", userDTO.getUsername());
        return new ProfilePictureDTO<>(Files.readAllBytes(file.toPath()), "image/png", String.valueOf(file.length()));
    }

    public void addProfilePicture(MultipartFile file, UserDTO userDTO) {
        User user = userRepository.findById(userDTO.getId()).orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        if (user.getDiscordId() != null)
            throw new ProfilePictureException("Discord users cannot upload profile pictures", HttpStatus.BAD_REQUEST);
        if (user.getProfilePictureName() != null)
            throw new ProfilePictureException("User already has a profile picture", HttpStatus.BAD_REQUEST);
        if (file.isEmpty()) throw new ProfilePictureException("File is empty", HttpStatus.BAD_REQUEST);

        String uploadDir = "src/main/resources/images/profile_pics/";
        createFileAndSave(file, user, uploadDir);

        log.info("Profile picture added for user: {}", userDTO.getUsername());
    }

    public void updateProfilePicture(MultipartFile file, UserDTO userDTO) {
        User user = userRepository.findById(userDTO.getId()).orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        if (user.getDiscordId() != null)
            throw new ProfilePictureException("Discord users cannot upload profile pictures", HttpStatus.BAD_REQUEST);
        if (user.getProfilePictureName() == null)
            throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);
        if (file.isEmpty()) throw new ProfilePictureException("File is empty", HttpStatus.BAD_REQUEST);

        deleteProfilePicture(userDTO);

        String uploadDir = "src/main/resources/images/profile_pics/";
        createFileAndSave(file, user, uploadDir);

        log.info("Profile picture updated for user: {}", userDTO.getUsername());
    }

    public void deleteProfilePicture(UserDTO userDTO) {

        if (userDTO.getDiscordId() != null)
            throw new ProfilePictureException("Discord users cannot delete their profile picture", HttpStatus.BAD_REQUEST);
        if (userDTO.getProfilePictureName() == null)
            throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);

        String uploadDir = "src/main/resources/images/profile_pics/";
        File file = new File(uploadDir + userDTO.getProfilePictureName());

        if (file.exists()) {
            if (file.delete()) {
                User user = userRepository.findByUsername(userDTO.getUsername()).orElseThrow();
                user.setProfilePictureName(null);
                userRepository.save(user);
                log.info("Profile picture deleted for user: {}", userDTO.getUsername());
                return;
            }
        }

        log.error("Error while deleting file: {}", file.getAbsolutePath());
        throw new ProfilePictureException("Failed to delete profile picture", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private void createFileAndSave(MultipartFile file, User user, String uploadDir) {
        File directory = new File(uploadDir);
        if (!directory.exists()) if (!directory.mkdirs()) return;

        String fileName = UUID.randomUUID() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        try {
            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            log.error("Error while copying file: {}", e.getMessage());
            throw new ProfilePictureException("Failed to save profile picture", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        user.setProfilePictureName(fileName);
        userRepository.save(user);

    }


    public void setPassword(String password, UserDTO userDTOSignedIn) {
        if (userDTOSignedIn.getPassword() != null)
            throw new PasswordException("User already has a password", HttpStatus.BAD_REQUEST);

        User user = userRepository.findById(userDTOSignedIn.getId()).orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));
        user.setPassword(passwordEncoder.encode(password));

        userRepository.save(user);
        log.info("Password set successfully for user: {}", userDTOSignedIn.getUsername());
    }

    private User resolveOrCreateUserFromJwt(Jwt jwt) {
        String subject = jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new UserNotFoundException("JWT subject is missing", HttpStatus.UNAUTHORIZED);
        }

        Optional<User> existingBySubject = userRepository.findByExternalId(subject);
        if (existingBySubject.isPresent()) {
            return syncUserData(existingBySubject.get(), jwt);
        }

        String email = jwt.getClaimAsString("email");
        if (email != null && !email.isBlank()) {
            Optional<User> existingByEmail = userRepository.findByEmail(email);
            if (existingByEmail.isPresent()) {
                User user = existingByEmail.get();
                user.setExternalId(subject);
                return syncUserData(user, jwt);
            }
        }

        Role userRole = roleRepository.findByName(EnumRole.ROLE_USER)
                .orElseThrow(() -> new RoleNotFoundException("Role is not found.", HttpStatus.NOT_FOUND));

        User user = new User();
        user.setExternalId(subject);
        user.setEmail((email == null || email.isBlank()) ? null : email);
        user.setUsername(generateUniqueUsername(extractPreferredUsername(jwt)));
        user.setProfilePictureName(jwt.getClaimAsString("picture"));
        user.setRoles(new HashSet<>(java.util.Set.of(userRole)));

        return userRepository.save(user);
    }

    private User syncUserData(User user, Jwt jwt) {
        boolean changed = false;

        String preferredUsername = extractPreferredUsername(jwt);
        if (preferredUsername != null && !preferredUsername.equals(user.getUsername())) {
            String uniqueUsername = generateUniqueUsername(preferredUsername, user.getId());
            if (!uniqueUsername.equals(user.getUsername())) {
                user.setUsername(uniqueUsername);
                changed = true;
            }
        }

        String email = jwt.getClaimAsString("email");
        if (email != null && !email.isBlank() && !email.equals(user.getEmail())) {
            user.setEmail(email);
            changed = true;
        }

        String picture = jwt.getClaimAsString("picture");
        if (picture != null && !picture.isBlank() && !picture.equals(user.getProfilePictureName())) {
            user.setProfilePictureName(picture);
            changed = true;
        }

        if (changed) {
            return userRepository.save(user);
        }

        return user;
    }

    private String extractPreferredUsername(Jwt jwt) {
        String preferred = firstNonBlank(
                jwt.getClaimAsString("username"),
                jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("name"),
                extractUsernameFromEmail(jwt.getClaimAsString("email")),
                "user_" + shortSub(jwt.getSubject())
        );
        return sanitizeUsername(preferred);
    }

    private String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return "user";
    }

    private String extractUsernameFromEmail(String email) {
        if (email == null || !email.contains("@")) {
            return null;
        }
        return email.substring(0, email.indexOf('@'));
    }

    private String shortSub(String subject) {
        if (subject == null || subject.isBlank()) {
            return UUID.randomUUID().toString().substring(0, 8);
        }
        return subject.length() <= 8 ? subject : subject.substring(0, 8);
    }

    private String sanitizeUsername(String value) {
        String sanitized = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "-");
        sanitized = sanitized.replaceAll("-+", "-").replaceAll("(^-|-$)", "");
        if (sanitized.isBlank()) {
            return "user";
        }
        return sanitized;
    }

    private String generateUniqueUsername(String baseUsername) {
        return generateUniqueUsername(baseUsername, null);
    }

    private String generateUniqueUsername(String baseUsername, Long currentUserId) {
        String base = baseUsername;
        int suffix = 1;
        String candidate = base;

        while (true) {
            boolean exists = currentUserId == null
                    ? userRepository.existsByUsername(candidate)
                    : userRepository.existsByUsernameAndIdNot(candidate, currentUserId);
            if (!exists) {
                return candidate;
            }
            candidate = base + "-" + suffix++;
        }
    }
}
