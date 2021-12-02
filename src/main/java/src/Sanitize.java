package src;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Sanitize {

    private static final String[] ALLOWED_TOKENS = {"{", "}", ":"};
    private static final String QUOTE_DECIMAL = "&#34;";

    public static JSONObject sanitizeToJSONObject(InputStream inputStream) {
        assert inputStream != null: "input stream must not be null";
        JSONObject jsonObject = inputStreamToJSONObject(inputStream);

        return new JSONObject(doSanitize(jsonObject.toString()));
    }

    public static byte[] sanitizeToByteArray(InputStream inputStream) {
        assert inputStream != null: "input stream must not be null";
        JSONObject jsonObject = inputStreamToJSONObject(inputStream);

        return doSanitize(jsonObject.toString()).getBytes(StandardCharsets.UTF_8);
    }

    public static JSONObject sanitize(String path) throws Exception {
        assert path != null: "path must specified";
        String content = new String(Files.readAllBytes(Paths.get(path)));
        String sanitizedContent = doSanitize(content);

        return new JSONObject(sanitizedContent);
    }

    public static String sanitizeToJsonString(InputStream inputStream) {
        assert inputStream != null: "input stream must not be null";
        return doSanitize(inputStreamToJSONObject(inputStream).toString());
    }

    private static JSONObject inputStreamToJSONObject(InputStream inputStream) {
        JSONTokener tokener = new JSONTokener(inputStream);
        return new JSONObject(tokener);
    }

    private static String doSanitize(String input) {
        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements(ALLOWED_TOKENS)
                .toFactory();

        return policy.sanitize(input).replace(QUOTE_DECIMAL, "\"");
    }
}
