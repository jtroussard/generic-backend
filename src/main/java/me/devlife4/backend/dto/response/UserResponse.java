package me.devlife4.backend.dto.response;

import lombok.Getter;
import me.devlife4.backend.entity.User;

@Getter
public class UserResponse {
    private final String username;

    public UserResponse(User user) {
        this.username = user.getUsername();
    }
}
