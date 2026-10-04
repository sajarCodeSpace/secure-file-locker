package com.sajar.securefilelocker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sajar.securefilelocker.dto.LoginRequest;
import com.sajar.securefilelocker.dto.RegisterRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/auth/register creates user and returns JWT token")
    void register_and_login_flow() throws Exception {
        String uniqueUser = "user_" + System.currentTimeMillis();
        RegisterRequest regRequest = new RegisterRequest(uniqueUser, "Password123!");

        // 1. Register
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is(uniqueUser)))
                .andExpect(jsonPath("$.token", notNullValue()));

        // 2. Register same username again -> 409 Conflict
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status", is(409)))
                .andExpect(jsonPath("$.message", containsString("Username already taken")));

        // 3. Login with correct credentials -> 200 OK
        LoginRequest loginRequest = new LoginRequest(uniqueUser, "Password123!");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is(uniqueUser)))
                .andExpect(jsonPath("$.token", notNullValue()));

        // 4. Login with wrong password -> 401 Unauthorized
        LoginRequest badLogin = new LoginRequest(uniqueUser, "WrongPassword!");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(badLogin)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)));
    }

    @Test
    @DisplayName("POST /api/auth/register with invalid input returns 400 Bad Request")
    void register_validationFailure() throws Exception {
        RegisterRequest invalidRequest = new RegisterRequest("ab", "short"); // min 3 chars username, min 8 chars pass

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status", is(400)));
    }
}
