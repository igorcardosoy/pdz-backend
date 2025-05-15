package br.app.pdz.api.service.user;

import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDetails getUserSignedInDetails() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        return (UserDetailsImpl) authentication.getPrincipal();
    }

    public byte[] getProfilePictureFile(String fileName) throws IOException {
        String uploadDir = "src/main/resources/images/profile_pics/";
        File file = new File(uploadDir + fileName);
        return Files.readAllBytes(file.toPath());
    }

    public boolean addProfilePicture(MultipartFile file, UserDetailsImpl userDetails) {
        User user = userRepository.findById(userDetails.getId()).orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getDiscordId() != null) return false;
        if (user.getProfilePictureName() != null) return false;

        String uploadDir = "src/main/resources/images/profile_pics/";

        return createFileAndSave(file, user, uploadDir);
    }

    public Boolean updateProfilePicture(MultipartFile file, UserDetails userDetails) {
        User user = userRepository.findById(((UserDetailsImpl) userDetails).getId()).orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getDiscordId() != null) return false;

        if (!deleteProfilePicture(userDetails)) log.info("There is no profile picture to delete");

        String uploadDir = "src/main/resources/images/profile_pics/";

        return createFileAndSave(file, user, uploadDir);
    }

    public Boolean deleteProfilePicture(UserDetails userDetails) {
        UserDetailsImpl userDetailsImpl = (UserDetailsImpl) userDetails;

        if (userDetailsImpl.getDiscordId() != null) return false;

        String uploadDir = "src/main/resources/images/profile_pics/";
        File file = new File(uploadDir + userDetailsImpl.getProfilePictureName());

        if (file.exists()) {
            if (file.delete()) {
                User user = userRepository.findByUsername(userDetailsImpl.getUsername()).orElseThrow();
                user.setProfilePictureName(null);
                userRepository.save(user);

                return true;
            }
        }

        return false;
    }

    private boolean createFileAndSave(MultipartFile file, User user, String uploadDir) {
        File directory = new File(uploadDir);
        if (!directory.exists())
            if (!directory.mkdirs()) return false;

        String fileName = UUID.randomUUID() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        try {
            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            return false;
        }

        user.setProfilePictureName(fileName);
        userRepository.save(user);

        return true;
    }


}
