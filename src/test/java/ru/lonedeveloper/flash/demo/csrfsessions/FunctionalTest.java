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

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@SpringBootTest
public class FunctionalTest {

    WebDriver driver;

    @Autowired
    WebApplicationContext context;

    @Before
    public void setup() {
        driver = MockMvcHtmlUnitDriverBuilder.webAppContextSetup(context, springSecurity()).build();
        driver.manage().deleteAllCookies();
    }

    @Test
    public void shouldRedirectToLoginWhenNotAuthorized() throws Exception {
        // when
        driver.get("http://localhost:8080/");

        // then
        assertThat(driver.getCurrentUrl(), containsString("/login"));
    }

    @Test
    public void shouldRedirectToIndexAfterLogin() throws Exception {
        // when
        driver.get("http://localhost:8080/login");
        driver.findElement(By.cssSelector("input[name=\"username\"]")).sendKeys(SecurityConfiguration.USER);
        driver.findElement(By.cssSelector("input[name=\"password\"]")).sendKeys(SecurityConfiguration.PASSWORD);
        driver.findElement(By.cssSelector("input[name=\"submit\"]")).click();

        // then
        assertThat(driver.getCurrentUrl(), endsWith("/"));
    }

}
