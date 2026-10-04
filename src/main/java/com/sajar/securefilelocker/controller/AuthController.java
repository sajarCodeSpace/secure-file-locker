package com.sajar.securefilelocker.controller;

import com.sajar.securefilelocker.dto.AuthResponse;
import com.sajar.securefilelocker.dto.LoginRequest;
import com.sajar.securefilelocker.dto.RegisterRequest;
import com.sajar.securefilelocker.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints for user registration and JWT authentication")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Creates a new user account with BCrypt password hashing (work factor 12) and returns a JWT token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Registration successful, JWT issued"),
            @ApiResponse(responseCode = "400", description = "Validation failure on username or password"),
            @ApiResponse(responseCode = "409", description = "Username already exists"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
    })
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(userService.register(request));
    }

    @PostMapping("/login")
    @Operation(summary = "Login existing user", description = "Authenticates credentials and returns a signed JWT Bearer token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Authentication successful, JWT issued"),
            @ApiResponse(responseCode = "401", description = "Invalid username or password"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
    })
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(userService.login(request));
    }
}
