package br.app.pdz.api.dto;

import br.app.pdz.api.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class UserDTO implements org.springframework.security.core.userdetails.UserDetails {

    private final Long id;
    private final String username;
    private final String discordId;
    private final String email;
    @JsonIgnore
    private final String password;
    private final String profilePictureName;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDTO(Long id, String username, String discordId, String email, String password, String profilePictureName,
                   Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.discordId = discordId;
        this.email = email;
        this.password = password;
        this.profilePictureName = profilePictureName;
        this.authorities = authorities;
    }

    public static UserDTO build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toUnmodifiableList());

        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getDiscordId(),
                user.getEmail(),
                user.getPassword(),
                user.getProfilePictureName(),
                authorities
        );
    }
}
