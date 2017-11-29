package ru.lonedeveloper.flash.demo.csrfsessions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

import javax.servlet.AsyncContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.ClassUtils;
import org.springframework.web.util.CookieGenerator;
import org.springframework.web.util.WebUtils;

//TODO: JD about copypastes from HttpSessionSecurityContextRepository
public class CookieSecurityContextRepository implements SecurityContextRepository {

    private final String cookieName;

    private final Log logger = LogFactory.getLog(this.getClass());

    /**
     * SecurityContext instance used to check for equality with default (unauthenticated) content
     */
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final boolean isServlet3 = ClassUtils.hasMethod(ServletRequest.class, "startAsync");

    public CookieSecurityContextRepository(final String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public SecurityContext loadContext(final HttpRequestResponseHolder requestResponseHolder) {
        final HttpServletRequest request = requestResponseHolder.getRequest();
        final HttpServletResponse response = requestResponseHolder.getResponse();

        SecurityContext context = readSecurityContextFromCookie(request);

        if (context == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No SecurityContext was available from the cookie. A new one will be created.");
            }
            context = SecurityContextHolder.createEmptyContext();
        }

        final SaveToCookieResponseWrapper wrappedResponse = new SaveToCookieResponseWrapper(response, request, context);
        requestResponseHolder.setResponse(wrappedResponse);

        if (isServlet3) {
            requestResponseHolder.setRequest(new Servlet3SaveToSessionRequestWrapper(request, wrappedResponse));
        }

        return context;
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
        final SaveToCookieResponseWrapper responseWrapper = WebUtils
                .getNativeResponse(response, SaveToCookieResponseWrapper.class);
        if (responseWrapper == null) {
            throw new IllegalStateException(
                    "Cannot invoke saveContext on response " + response
                            + ". You must use the HttpRequestResponseHolder.response after invoking loadContext");
        }
        // saveContext() might already be called by the response wrapper
        // if something in the chain called sendError() or sendRedirect(). This ensures we
        // only call it
        // once per request.
        if (!responseWrapper.isContextSaved()) {
            responseWrapper.saveContext(context);
        }
    }

    @Override
    public boolean containsContext(final HttpServletRequest request) {
        final Cookie cookie = WebUtils.getCookie(request, cookieName);
        return cookie != null;
    }

    final class SaveToCookieResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

        private final HttpServletRequest request;
        private final SecurityContext contextBeforeExecution;
        private final Authentication authBeforeExecution;

        /**
         * Takes the parameters required to call <code>saveContext()</code> successfully in addition to the request and the
         * response object we are wrapping.
         *
         * @param request the request object (used to obtain the session, if one exists).
         * @param httpSessionExistedAtStartOfRequest indicates whether there was a session in place before the filter chain
         *            executed. If this is true, and the session is found to be null, this indicates that it was invalidated
         *            during the request and a new session will now be created.
         * @param context the context before the filter chain executed. The context will only be stored if it or its contents
         *            changed during the request.
         */
        SaveToCookieResponseWrapper(
                final HttpServletResponse response,
                final HttpServletRequest request,
                final SecurityContext context) {
            super(response, true); // TODO: try with false?
            this.request = request;
            this.contextBeforeExecution = context;
            this.authBeforeExecution = context.getAuthentication();
        }

        /**
         * Stores the supplied security context in the session (if available) and if it has changed since it was set at the
         * start of the request. If the AuthenticationTrustResolver identifies the current user as anonymous, then the context
         * will not be stored.
         *
         * @param context the context object obtained from the SecurityContextHolder after the request has been processed by the
         *            filter chain. SecurityContextHolder.getContext() cannot be used to obtain the context as it has already
         *            been cleared by the time this method is called.
         *
         */
        @Override
        protected void saveContext(final SecurityContext context) {
            final Authentication authentication = context.getAuthentication();

            // See SEC-776
            if (authentication == null || trustResolver.isAnonymous(authentication)) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                            "SecurityContext is empty or contents are anonymous - context will not be stored in HttpSession.");
                }

                if (containsContext(request) && authBeforeExecution != null) {
                    // SEC-1587 A non-anonymous context may still be in the session
                    // SEC-1735 remove if the contextBeforeExecution was not anonymous
                    deleteSecurityContextCookie();
                }
                return;
            }

            // If HttpSession exists, store current SecurityContext but only if it has
            // actually changed in this thread (see SEC-37, SEC-1307, SEC-1528)
            // We may have a new session, so check also whether the context attribute
            // is set SEC-1561
            if (contextChanged(context) || containsContext(request)) {
                createSecurityContextCookie(context);

                if (logger.isDebugEnabled()) {
                    logger.debug("SecurityContext '" + context + "' stored to the cookie");
                }
            }
        }

        private boolean contextChanged(final SecurityContext context) {
            return context != contextBeforeExecution || context.getAuthentication() != authBeforeExecution;
        }

        private void createSecurityContextCookie(final SecurityContext context) {
            final CookieGenerator cookieGenerator = new CookieGenerator();
            cookieGenerator.setCookieName(cookieName);
            cookieGenerator.setCookiePath("/");
            cookieGenerator.setCookieHttpOnly(false);
            cookieGenerator.setCookieMaxAge(-1);
            try {
                cookieGenerator.addCookie(this, serializeSecurityContext(context));
            } catch (final Exception e) {
                throw new RuntimeException("Error while serializing the security context into the cookie", e);
            }
        }

        private void deleteSecurityContextCookie() {
            addHeader(HttpHeaders.SET_COOKIE, cookieName + "=\"\"; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
        }

    }

    private static class Servlet3SaveToSessionRequestWrapper extends HttpServletRequestWrapper {

        private final SaveContextOnUpdateOrErrorResponseWrapper response;

        public Servlet3SaveToSessionRequestWrapper(
                final HttpServletRequest request,
                final SaveContextOnUpdateOrErrorResponseWrapper response) {
            super(request);
            this.response = response;
        }

        @Override
        public AsyncContext startAsync() {
            response.disableSaveOnResponseCommitted();
            return super.startAsync();
        }

        @Override
        public AsyncContext startAsync(final ServletRequest servletRequest, final ServletResponse servletResponse)
                throws IllegalStateException {
            response.disableSaveOnResponseCommitted();
            return super.startAsync(servletRequest, servletResponse);
        }
    }
}
