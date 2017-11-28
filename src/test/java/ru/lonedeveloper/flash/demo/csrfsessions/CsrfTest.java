package ru.lonedeveloper.flash.demo.csrfsessions;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.htmlunit.webdriver.MockMvcHtmlUnitDriverBuilder;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@SpringBootTest
public class CsrfTest {

    private static final String CSRF_TOKEN_COOKIE = "XSRF-TOKEN";

    WebDriver driver;

    @Autowired
    WebApplicationContext context;

    @Before
    public void setup() {
        driver = MockMvcHtmlUnitDriverBuilder.webAppContextSetup(context, springSecurity()).build();
        driver.manage().deleteAllCookies();
    }

    @Test
    public void shouldGenerateCsrfTokenIfAbsent() throws Exception {
        // when
        driver.get("http://localhost:8080/");

        // then
        assertThat(driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE), is(not(nullValue())));
    }

    @Test
    public void shouldNotRegenerateCsrfTokenOnPageRefreshWhenAnonymous() throws Exception {
        // given
        driver.get("http://localhost:8080/");
        final String csrfTokenValue = driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE).getValue();

        // when
        driver.get("http://localhost:8080/");

        // then
        assertThat(driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE), hasProperty("value", is(csrfTokenValue)));
    }

    @Test
    public void shouldNotRegenerateCsrfTokenOnPageRefreshWhenLoggedIn() throws Exception {
        // given
        driver.get("http://localhost:8080/login");
        driver.findElement(By.cssSelector("input[name=\"username\"]")).sendKeys(SecurityConfiguration.USER);
        driver.findElement(By.cssSelector("input[name=\"password\"]")).sendKeys(SecurityConfiguration.PASSWORD);
        driver.findElement(By.cssSelector("input[name=\"submit\"]")).click();
        final String csrfTokenValue = driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE).getValue();

        // when
        driver.get("http://localhost:8080/");

        // then
        assertThat(driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE), hasProperty("value", is(csrfTokenValue)));
    }

    @Test
    public void shouldRegenerateCsrfTokenOnLogin() throws Exception {
        // when
        driver.get("http://localhost:8080/login");
        final String csrfTokenValue = driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE).getValue();
        driver.findElement(By.cssSelector("input[name=\"username\"]")).sendKeys(SecurityConfiguration.USER);
        driver.findElement(By.cssSelector("input[name=\"password\"]")).sendKeys(SecurityConfiguration.PASSWORD);
        driver.findElement(By.cssSelector("input[name=\"submit\"]")).click();

        // then
        assertThat(
                driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE),
                allOf(is(not(nullValue())), hasProperty("value", is(not(csrfTokenValue)))));
    }

    @Test
    public void shouldRegenerateCsrfTokenOnLogout() throws Exception {
        // given
        driver.get("http://localhost:8080/login");
        driver.findElement(By.cssSelector("input[name=\"username\"]")).sendKeys(SecurityConfiguration.USER);
        driver.findElement(By.cssSelector("input[name=\"password\"]")).sendKeys(SecurityConfiguration.PASSWORD);
        driver.findElement(By.cssSelector("input[name=\"submit\"]")).click();
        final String csrfTokenValue = driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE).getValue();

        // when
        driver.findElement(By.id("logout-button")).click();

        // then
        assertThat(
                driver.manage().getCookieNamed(CSRF_TOKEN_COOKIE),
                allOf(is(not(nullValue())), hasProperty("value", is(not(csrfTokenValue)))));
    }

}
