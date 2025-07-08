package br.app.pdz.api.controller;

import br.app.pdz.api.dto.ProfilePictureDTO;
import br.app.pdz.api.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@Log4j2
@RequestMapping("/pdz-api/users")
@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public org.springframework.security.core.userdetails.UserDetails getUserDatails() {
        return userService.getUserDTOSignedIn();
    }

    @GetMapping("/profile-picture")
    public ResponseEntity<?> getProfilePicture() throws IOException {
        ProfilePictureDTO<?> profilePictureDTO = userService.getProfilePicture(userService.getUserDTOSignedIn());

        return ResponseEntity.ok()
                .header("Content-Type", profilePictureDTO.contentType())
                .header("Content-Length", profilePictureDTO.length())
                .body(profilePictureDTO.profilePicture());

    }

    @PostMapping("/profile-picture")
    public ResponseEntity<String> uploadProfilePicture(@RequestParam("profilePicture") MultipartFile file) {
        userService.addProfilePicture(file, userService.getUserDTOSignedIn());

        return ResponseEntity.status(HttpStatus.CREATED).body("Success: Profile picture uploaded successfully");
    }

    @PutMapping("/profile-picture")
    public ResponseEntity<String> updateProfilePicture(@RequestParam("profilePicture") MultipartFile file) {
        userService.updateProfilePicture(file, userService.getUserDTOSignedIn());

        return ResponseEntity.ok("Success: Profile picture updated successfully");
    }

    @DeleteMapping("/profile-picture")
    public ResponseEntity<String> deleteProfilePicture() {
        userService.deleteProfilePicture(userService.getUserDTOSignedIn());

        return ResponseEntity.ok("Success: Profile picture deleted successfully");
    }

}
