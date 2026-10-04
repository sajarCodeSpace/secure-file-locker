package com.sajar.securefilelocker.service;

import com.sajar.securefilelocker.dto.AuthResponse;
import com.sajar.securefilelocker.dto.LoginRequest;
import com.sajar.securefilelocker.dto.RegisterRequest;
import com.sajar.securefilelocker.exception.ApiExceptions;
import com.sajar.securefilelocker.model.User;
import com.sajar.securefilelocker.repository.UserRepository;
import com.sajar.securefilelocker.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            log.warn("Registration failed: username '{}' already taken", request.username());
            throw new ApiExceptions.UsernameTakenException(request.username());
        }

        User user = User.builder()
                .username(request.username())
                .passwordHash(passwordEncoder.encode(request.password()))
                .build();

        User saved = userRepository.save(user);
        log.info("AUDIT: User successfully registered [userId={}, username={}]", saved.getId(), saved.getUsername());
        String token = jwtUtil.generateToken(saved.getUsername(), saved.getId());
        return new AuthResponse(token, saved.getUsername());
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> {
                    log.warn("AUDIT: Login failed - unknown user '{}'", request.username());
                    return new ApiExceptions.InvalidCredentialsException();
                });

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            log.warn("AUDIT: Login failed - invalid password for user '{}'", request.username());
            throw new ApiExceptions.InvalidCredentialsException();
        }

        log.info("AUDIT: User logged in successfully [userId={}, username={}]", user.getId(), user.getUsername());
        String token = jwtUtil.generateToken(user.getUsername(), user.getId());
        return new AuthResponse(token, user.getUsername());
    }
}
