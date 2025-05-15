package br.app.pdz.api.service.user;

import br.app.pdz.api.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class UserDetailsImpl implements UserDetails {

    private final Long id;
    private final String username;
    private final String discordId;
    private final String email;
    @JsonIgnore
    private final String password;
    private final String profilePictureName;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String discordId, String email, String password, String profilePictureName,
                           Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.discordId = discordId;
        this.email = email;
        this.password = password;
        this.profilePictureName = profilePictureName;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toUnmodifiableList());

        String profilePicture;
        if (user.getDiscordId() != null) {
            profilePicture = String.format("https://cdn.discordapp.com/avatars/%s/%s.png", user.getDiscordId(), user.getProfilePictureName());
        } else {
            profilePicture = user.getProfilePictureName();
        }

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getDiscordId(),
                user.getEmail(),
                user.getPassword(),
                profilePicture,
                authorities
        );
    }
}
