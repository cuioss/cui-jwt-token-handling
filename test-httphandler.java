import de.cuioss.tools.net.http.HttpHandler;
import java.net.URI;

public class TestHttpHandler {
    public static void main(String[] args) {
        try {
            HttpHandler.HttpHandlerBuilder builder = HttpHandler.builder();
            HttpHandler handler = builder.uri(URI.create("https://example.com")).build();

            // Let's see what methods are available on the built handler
            System.out.println("URI: " + handler.getUri());
            System.out.println("URL: " + handler.getUrl());
            System.out.println("SSL Context: " + handler.getSslContext());

            // Try to find timeout-related methods
            try {
                java.lang.reflect.Method[] methods = handler.getClass().getMethods();
                System.out.println("Available methods:");
                for (java.lang.reflect.Method method : methods) {
                    if (method.getName().toLowerCase().contains("timeout")) {
                        System.out.println("  - " + method.getName() + "()");
                    }
                }
            } catch (Exception e) {
                System.out.println("Error reflecting methods: " + e.getMessage());
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
