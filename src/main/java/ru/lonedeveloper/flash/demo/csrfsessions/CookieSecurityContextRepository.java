package ru.lonedeveloper.flash.demo.csrfsessions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.util.CookieGenerator;
import org.springframework.web.util.WebUtils;

public class CookieSecurityContextRepository implements SecurityContextRepository {

    private final String cookieName;

    public CookieSecurityContextRepository(final String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public SecurityContext loadContext(final HttpRequestResponseHolder requestResponseHolder) {
        final HttpServletRequest request = requestResponseHolder.getRequest();
        final SecurityContext context = readSecurityContextFromCookie(request);

        return context == null ? SecurityContextHolder.createEmptyContext() : context;
    }

    private SecurityContext readSecurityContextFromCookie(final HttpServletRequest request) {
        final Cookie cookie = WebUtils.getCookie(request, cookieName);
        if (cookie == null) {
            return SecurityContextHolder.createEmptyContext();
        }

        try {
            return deserializeSecurityContext(cookie.getValue());
        } catch (final Exception e) {
            return SecurityContextHolder.createEmptyContext();
        }
    }

    private SecurityContext deserializeSecurityContext(final String serializedObject)
            throws IOException, ClassNotFoundException {
        final byte[] bytes = Base64.getDecoder().decode(serializedObject);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes); ObjectInputStream ios = new ObjectInputStream(bais)) {
            return (SecurityContext) ios.readObject();
        }
    }

    private String serializeSecurityContext(final SecurityContext securityContext) throws IOException, ClassNotFoundException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(securityContext);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    @Override
    public void saveContext(
            final SecurityContext context,
            final HttpServletRequest request,
            final HttpServletResponse response) {
        final CookieGenerator cookieGenerator = new CookieGenerator();
        cookieGenerator.setCookieName(cookieName);
        cookieGenerator.setCookiePath("/");
        cookieGenerator.setCookieHttpOnly(false);
        cookieGenerator.setCookieMaxAge(-1);
        try {
            cookieGenerator.addCookie(response, serializeSecurityContext(context));
        } catch (final Exception e) {
            throw new RuntimeException("Error while serializing the security context into the cookie", e);
        }
    }

    @Override
    public boolean containsContext(final HttpServletRequest request) {
        final Cookie cookie = WebUtils.getCookie(request, cookieName);
        return cookie != null;
    }

}
