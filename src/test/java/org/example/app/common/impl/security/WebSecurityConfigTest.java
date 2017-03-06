package org.example.app.common.impl.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import javax.inject.Inject;
import javax.servlet.Filter;

import org.example.app.TestConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = TestConfig.class)
// @SpringBootTest(webEnvironment = WebEnvironment.NONE, classes = { TestConfig.class })
@WebAppConfiguration
public class WebSecurityConfigTest {

  private static final String URI_TEST = "/test";

  private static final String URI_LOGIN = "/login";

  private static final String URI_TEST_SERVICE = "/test/services/rest/test-service/test-resource/1";

  private static final String LOGIN = "admin";

  @Inject
  private WebApplicationContext webApplicationContext;

  @Inject
  private Filter springSecurityFilterChain;

  private MockMvc mockMvc;

  @Before
  public void setUp() {

    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext)
        .addFilters(this.springSecurityFilterChain).build();
  }

  private ResultActions perform(MockHttpServletRequestBuilder requestBuilder) throws Exception {

    return perform(requestBuilder, false);
  }

  private ResultActions perform(MockHttpServletRequestBuilder requestBuilder, boolean createCsrfToken)
      throws Exception {

    SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(LOGIN, "admin"));
    MockHttpSession session = new MockHttpSession();
    SecurityContext context = SecurityContextHolder.getContext();
    session.setAttribute("SPRING_SECURITY_CONTEXT", context);
    if (createCsrfToken) {
      String headerName = "X-CSRF-TOKEN";
      String token = UUID.randomUUID().toString();
      DefaultCsrfToken csrfToken = new DefaultCsrfToken(headerName, "_csrf", token);
      session.setAttribute(HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN"), csrfToken);
      requestBuilder.header(headerName, token);
    }
    requestBuilder.session(session);
    return this.mockMvc.perform(requestBuilder);
  }

  /**
   * In diesem Test werden einige GET-Requests auf Erfolg ohne CSRF-Token getestet.
   *
   * @throws Exception falls der Test fehlschlägt.
   */
  @Test
  public void testGet() throws Exception {

    this.mockMvc.perform(get(URI_LOGIN)).andExpect(status().isOk());
    perform(get(URI_TEST)).andExpect(status().isOk());
    perform(get(URI_TEST_SERVICE)).andExpect(status().isOk());
  }

  /**
   * In diesem Test werden einige POST-Requests ohne CSRF-Token auf URLs durchgeführt, die keinen CSRF-Schutz erfordern.
   *
   * @throws Exception falls der Test fehlschlägt.
   */
  @Test
  public void testPostWithoutCsrfProtection() throws Exception {

    perform(post(URI_LOGIN).param("username", LOGIN).param("password", LOGIN)).andExpect(status().is3xxRedirection());
    perform(post(URI_TEST)).andExpect(status().isOk());
    perform(post(URI_TEST_SERVICE)).andExpect(status().isOk());
  }

  /**
   * In diesem Test werden POST-Requests auf URLs mit CSRF-Schutz durchgeführt und getestet, dass diese nur mit gültigem
   * CSRF-Token funktionieren.
   *
   * @throws Exception falls der Test fehlschlägt.
   */
  @Test
  public void testPostWithCsrfProtection() throws Exception {

    perform(post(URI_TEST_SERVICE), false).andExpect(status().is(403));
    perform(post(URI_TEST_SERVICE), true).andExpect(status().isOk());
  }

}
