package ember;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class EmberFilter implements Filter {
    private final EmberClient client;

    public EmberFilter(EmberClient client) {
        this.client = client;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // no-op
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            chain.doFilter(request, response);
        } catch (Exception ex) {
            if (client != null && request instanceof HttpServletRequest) {
                HttpServletRequest http = (HttpServletRequest) request;
                Map<String, String> tags = new HashMap<>();
                tags.put("method", http.getMethod());
                tags.put("path", http.getRequestURI());
                try {
                    client.captureError(ex, tags, null, null);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            if (ex instanceof ServletException) {
                throw (ServletException) ex;
            }
            if (ex instanceof IOException) {
                throw (IOException) ex;
            }
            throw new ServletException(ex);
        }
    }

    @Override
    public void destroy() {
        // no-op
    }
}
