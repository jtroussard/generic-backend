package me.devlife4.backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class WebApplicationBackendApplicationTests {

	@Test
	void contextLoads() {
		assertTrue(true, "Application context should load successfully.");
	}

	@Test
	void contextLoadsMainCheck() {
		assertDoesNotThrow(() -> WebApplicationBackendApplication.main(new String[]{}));
	}

}
