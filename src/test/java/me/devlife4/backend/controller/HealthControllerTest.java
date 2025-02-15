package me.devlife4.backend.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class HealthControllerTest {

    private HealthController healthController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        healthController = new HealthController();
    }

    @Test
    void healthCheckShouldReturnOk() {
        String response = healthController.healthCheck();

        assertNotNull(response);
        assertEquals("OK", response);
    }

}
