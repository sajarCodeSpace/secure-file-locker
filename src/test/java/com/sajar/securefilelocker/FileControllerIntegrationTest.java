package com.sajar.securefilelocker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sajar.securefilelocker.controller.FileController.DownloadRequest;
import com.sajar.securefilelocker.dto.RegisterRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class FileControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String registerAndGetToken(String username) throws Exception {
        RegisterRequest reg = new RegisterRequest(username, "Password123!");
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(reg)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return node.get("token").asText();
    }

    @Test
    @DisplayName("Unauthenticated request to file endpoints returns 401 Unauthorized")
    void unauthenticatedAccess_isDenied() throws Exception {
        mockMvc.perform(get("/api/files"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Full lifecycle: upload, list, download (correct/wrong pass), IDOR prevention, and delete")
    void fileLifecycle_and_IDOR_prevention() throws Exception {
        long ts = System.currentTimeMillis();
        String tokenUserA = registerAndGetToken("alice_" + ts);
        String tokenUserB = registerAndGetToken("bob_" + ts);

        byte[] secretData = "Confidential financial report 2026".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "report.txt", "text/plain", secretData
        );

        // 1. User A uploads an encrypted file
        MvcResult uploadResult = mockMvc.perform(multipart("/api/files")
                        .file(multipartFile)
                        .param("password", "SuperSecretFilePass1!")
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", notNullValue()))
                .andExpect(jsonPath("$.originalFilename", is("report.txt")))
                .andReturn();

        JsonNode uploadJson = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        long fileId = uploadJson.get("id").asLong();

        // 2. User A lists files - sees uploaded file
        mockMvc.perform(get("/api/files")
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$[0].originalFilename", is("report.txt")));

        // 3. User A downloads file with correct password -> receives original decrypted bytes
        DownloadRequest correctPassReq = new DownloadRequest("SuperSecretFilePass1!");
        MvcResult downloadResult = mockMvc.perform(post("/api/files/" + fileId + "/download")
                        .header("Authorization", "Bearer " + tokenUserA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(correctPassReq)))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("report.txt")))
                .andReturn();

        assertArrayEquals(secretData, downloadResult.getResponse().getContentAsByteArray());

        // 4. User A attempts download with WRONG password -> 401 Unauthorized
        DownloadRequest wrongPassReq = new DownloadRequest("WrongPassword999!");
        mockMvc.perform(post("/api/files/" + fileId + "/download")
                        .header("Authorization", "Bearer " + tokenUserA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongPassReq)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.message", containsString("Incorrect password or corrupted file")));

        // 5. IDOR Isolation Test: User B attempts to download User A's file -> 404 Not Found
        mockMvc.perform(post("/api/files/" + fileId + "/download")
                        .header("Authorization", "Bearer " + tokenUserB)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(correctPassReq)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status", is(404)));

        // 6. IDOR Isolation Test: User B attempts to delete User A's file -> 404 Not Found
        mockMvc.perform(delete("/api/files/" + fileId)
                        .header("Authorization", "Bearer " + tokenUserB))
                .andExpect(status().isNotFound());

        // 7. User A deletes their own file -> 204 No Content
        mockMvc.perform(delete("/api/files/" + fileId)
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isNoContent());

        // 8. User A attempts to download deleted file -> 404 Not Found
        mockMvc.perform(post("/api/files/" + fileId + "/download")
                        .header("Authorization", "Bearer " + tokenUserA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(correctPassReq)))
                .andExpect(status().isNotFound());
    }
}
