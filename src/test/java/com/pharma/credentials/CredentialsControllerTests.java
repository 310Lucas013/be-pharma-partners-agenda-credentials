package com.pharma.credentials;

import com.google.gson.Gson;
import com.pharma.credentials.config.JwtRequestFilter;
import com.pharma.credentials.config.JwtTokenUtil;
import com.pharma.credentials.config.WebSecurityConfig;
import com.pharma.credentials.controller.JwtAuthenticationController;
import com.pharma.credentials.models.UserDao;
import com.pharma.credentials.service.JwtUserDetailsService;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*@RunWith(SpringRunner.class)
@ContextConfiguration(classes=CredentialsApplication.class)
@WebMvcTest(JwtAuthenticationController.class)*/
class CredentialsControllerTests {

/*	@Autowired
	private MockMvc mvc;

	private final Gson gson = new Gson();

	@MockBean
	private JwtUserDetailsService service;

	@Before
	public void setUp() {
		MockitoAnnotations.openMocks(this);
	}

	@Test
	public void contextLoads() {
		assertThat(service).isNotNull();
	}

	@Test
	public void getAllUsersAPI()
			throws Exception {
		UserDao user1 = new UserDao();
		UserDao user2 = new UserDao();

		user1.setUsername("Test1");
		user2.setUsername("Test2");

		List<UserDao> allUsers = new ArrayList<>();
		allUsers.add(user1);
		allUsers.add(user2);

		given(service.getAll()).willReturn(allUsers);
		mvc.perform(MockMvcRequestBuilders
				.get("/credentials/all")
				.accept(MediaType.APPLICATION_JSON))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$[*].username").isNotEmpty());
	}*/
}
