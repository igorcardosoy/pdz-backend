package br.app.pdz.api.controller;

import br.app.pdz.api.service.user.UserDetailsImpl;
import br.app.pdz.api.service.user.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@Log4j2
@RequestMapping("/user")
@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public UserDetails getUserDatails() {
        return userService.getUserSignedInDetails();
    }

    @GetMapping("/profile-picture")
    public ResponseEntity<?> getProfilePicture() throws IOException {
        UserDetailsImpl userDetails = (UserDetailsImpl) userService.getUserSignedInDetails();

        if (userDetails.getDiscordId() != null)
            return ResponseEntity.ok(userDetails.getProfilePictureName());

        if (userDetails.getProfilePictureName() == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Error: Profile picture not found");

        byte[] profilePicture = userService.getProfilePictureFile(userDetails.getProfilePictureName());

        if (profilePicture == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Error: Profile picture not found");


        return ResponseEntity.ok()
                .header("Content-Type", "image/png")
                .header("Content-Length", String.valueOf(profilePicture.length))
                .body(profilePicture);
    }

    @PostMapping("/profile-picture")
    public ResponseEntity<String> uploadProfilePicture(@RequestParam("profilePicture") MultipartFile file) {
        if (file.isEmpty())
            return ResponseEntity.badRequest().body("Error: File is empty");

        UserDetailsImpl userDetails = (UserDetailsImpl) userService.getUserSignedInDetails();

        if (userDetails.getProfilePictureName() != null)
            return ResponseEntity.badRequest().body("Error: Profile picture already exists");

        if (userService.addProfilePicture(file, userDetails))
            return ResponseEntity.ok("Success: Profile picture uploaded successfully");

        if  (userDetails.getDiscordId() != null)
            return ResponseEntity.badRequest().body("Error: Discord users cannot upload a profile picture");

        return ResponseEntity.badRequest().body("Error: Failed to upload profile picture");
    }

    @PutMapping("/profile-picture")
    public ResponseEntity<String> updateProfilePicture(@RequestParam("profilePicture") MultipartFile file) {
        if (file.isEmpty())
            return ResponseEntity.badRequest().body("Error: File is empty");

        UserDetailsImpl userDetails = (UserDetailsImpl) userService.getUserSignedInDetails();

        if (userService.updateProfilePicture(file, userDetails))
            return ResponseEntity.ok("Success: Profile picture updated successfully");

        if  (userDetails.getDiscordId() != null)
            return ResponseEntity.badRequest().body("Error: Discord users cannot update their profile picture");

        return ResponseEntity.badRequest().body("Error: Failed to update profile picture");
    }

    @DeleteMapping("/profile-picture")
    public ResponseEntity<String> deleteProfilePicture() {
        UserDetailsImpl userDetails = (UserDetailsImpl) userService.getUserSignedInDetails();

        if (userDetails.getDiscordId() != null)
            return ResponseEntity.badRequest().body("Error: Discord users cannot delete their profile picture");

        if (userService.deleteProfilePicture(userDetails))
            return ResponseEntity.ok("Success: Profile picture deleted successfully");

        return ResponseEntity.badRequest().body("Error: Failed to delete profile picture");
    }



}
