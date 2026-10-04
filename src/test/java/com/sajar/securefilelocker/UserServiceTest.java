package com.sajar.securefilelocker;

import com.sajar.securefilelocker.dto.AuthResponse;
import com.sajar.securefilelocker.dto.LoginRequest;
import com.sajar.securefilelocker.dto.RegisterRequest;
import com.sajar.securefilelocker.exception.ApiExceptions;
import com.sajar.securefilelocker.model.User;
import com.sajar.securefilelocker.repository.UserRepository;
import com.sajar.securefilelocker.security.JwtUtil;
import com.sajar.securefilelocker.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private UserService userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        sampleUser = User.builder()
                .id(1L)
                .username("testuser")
                .passwordHash("hashedPassword123")
                .build();
    }

    @Test
    @DisplayName("Register with available username hashes password and issues JWT")
    void register_success() {
        RegisterRequest request = new RegisterRequest("testuser", "securePass123");

        when(userRepository.existsByUsername("testuser")).thenReturn(false);
        when(passwordEncoder.encode("securePass123")).thenReturn("hashedPassword123");
        when(userRepository.save(any(User.class))).thenReturn(sampleUser);
        when(jwtUtil.generateToken("testuser", 1L)).thenReturn("mocked.jwt.token");

        AuthResponse response = userService.register(request);

        assertNotNull(response);
        assertEquals("testuser", response.username());
        assertEquals("mocked.jwt.token", response.token());
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Register with duplicate username throws UsernameTakenException")
    void register_duplicateUsername_throwsException() {
        RegisterRequest request = new RegisterRequest("testuser", "securePass123");

        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        assertThrows(ApiExceptions.UsernameTakenException.class, () -> userService.register(request));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Login with valid credentials returns JWT")
    void login_success() {
        LoginRequest request = new LoginRequest("testuser", "correctPassword");

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPassword", sampleUser.getPasswordHash())).thenReturn(true);
        when(jwtUtil.generateToken("testuser", 1L)).thenReturn("valid.jwt.token");

        AuthResponse response = userService.login(request);

        assertNotNull(response);
        assertEquals("testuser", response.username());
        assertEquals("valid.jwt.token", response.token());
    }

    @Test
    @DisplayName("Login with nonexistent username throws InvalidCredentialsException")
    void login_unknownUser_throwsException() {
        LoginRequest request = new LoginRequest("unknownUser", "anyPassword");

        when(userRepository.findByUsername("unknownUser")).thenReturn(Optional.empty());

        assertThrows(ApiExceptions.InvalidCredentialsException.class, () -> userService.login(request));
    }

    @Test
    @DisplayName("Login with wrong password throws InvalidCredentialsException")
    void login_wrongPassword_throwsException() {
        LoginRequest request = new LoginRequest("testuser", "wrongPassword");

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("wrongPassword", sampleUser.getPasswordHash())).thenReturn(false);

        assertThrows(ApiExceptions.InvalidCredentialsException.class, () -> userService.login(request));
    }
}
