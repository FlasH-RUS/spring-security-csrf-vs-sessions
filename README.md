# Spring Security CSRF vs Session Management playground

This is a small investigation project to finally understand how does Spring Security cookie-based CSRF works with its own Session Management.
The idea is to have several branches with different configurations (stateless session management, disabled session management, etc.) and see if and how the behavior changes depending on that.

## Expected CSRF behavior
- CSRF token is generated if absent (= first visit to the application)
- CSRF token is re-generated after successful login
- CSRF token is re-generated after successful logout
- CSRF token is **not** regenerated on any other occasion 

## Setup
- Spring Boot 1.5.8
- Default security with in-memory authentication and cookie-based CSRF enabled (_CookieCsrfTokenRepository_)
- Index page (/) that requires authentication
- (Functional tests)[src/test/java/ru/lonedeveloper/flash/demo/csrfsessions/FunctionalTest.java] to check the application behavior
- (CSRF tests)[src/test/java/ru/lonedeveloper/flash/demo/csrfsessions/FunctionalTest.java] to check CSRF-related behavior
