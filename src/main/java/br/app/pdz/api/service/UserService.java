package br.app.pdz.api.service;

import br.app.pdz.api.dto.ProfilePictureDTO;
import br.app.pdz.api.dto.UserDTO;
import br.app.pdz.api.model.exception.ProfilePictureException;
import br.app.pdz.api.model.User;
import br.app.pdz.api.model.exception.UserNotFoundException;
import br.app.pdz.api.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDTO loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDTO.build(user);
    }

    public UserDTO getUserDTOSignedIn() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        return (UserDTO) authentication.getPrincipal();
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

        if (userDTO.getProfilePictureName() == null) throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);


        String uploadDir = "src/main/resources/images/profile_pics/";
        File file = new File(uploadDir + userDTO.getProfilePictureName());

        log.info("Profile picture retrieved for user: {}", userDTO.getUsername());
        return new ProfilePictureDTO<>(Files.readAllBytes(file.toPath()), "image/png", String.valueOf(file.length()));
    }

    public void addProfilePicture(MultipartFile file, UserDTO userDTO) {
        User user = userRepository.findById(userDTO.getId()).orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        if (user.getDiscordId() != null) throw new ProfilePictureException("Discord users cannot upload profile pictures", HttpStatus.BAD_REQUEST);
        if (user.getProfilePictureName() != null) throw new ProfilePictureException("User already has a profile picture", HttpStatus.BAD_REQUEST);
        if (file.isEmpty()) throw new ProfilePictureException("File is empty", HttpStatus.BAD_REQUEST);

        String uploadDir = "src/main/resources/images/profile_pics/";
        createFileAndSave(file, user, uploadDir);

        log.info("Profile picture added for user: {}", userDTO.getUsername());
    }

    public void updateProfilePicture(MultipartFile file, UserDTO userDTO) {
        User user = userRepository.findById(userDTO.getId()).orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        if (user.getDiscordId() != null) throw new ProfilePictureException("Discord users cannot upload profile pictures", HttpStatus.BAD_REQUEST);
        if (user.getProfilePictureName() == null) throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);
        if (file.isEmpty()) throw new ProfilePictureException("File is empty", HttpStatus.BAD_REQUEST);

        deleteProfilePicture(userDTO);

        String uploadDir = "src/main/resources/images/profile_pics/";
        createFileAndSave(file, user, uploadDir);

        log.info("Profile picture updated for user: {}", userDTO.getUsername());
    }

    public void deleteProfilePicture(UserDTO userDTO) {

        if (userDTO.getDiscordId() != null) throw new ProfilePictureException("Discord users cannot delete their profile picture", HttpStatus.BAD_REQUEST);
        if (userDTO.getProfilePictureName() == null) throw new ProfilePictureException("User does not have a profile picture", HttpStatus.BAD_REQUEST);

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


}
