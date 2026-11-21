import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class URLAnalyzer implements Analyzer {
    private static final Pattern IPV4 = Pattern.compile(
        "^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$");
    private static final List<String> SHORTENERS = Arrays.asList(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly");
    private static final List<String> SUSPICIOUS_PATH_WORDS = Arrays.asList(
        "login", "verify", "account", "update", "secure", "password", "signin");

    @Override
    public List<String> analyze(String input) {
        List<String> findings = new ArrayList<String>();
        if (input == null || input.trim().isEmpty()) {
            findings.add("Empty URL input");
            return findings;
        }

        String candidate = input.trim();
        if (!candidate.matches("(?i)^https?://.*")) {
            candidate = "http://" + candidate;
        }

        try {
            URI uri = new URI(candidate);
            String host = uri.getHost();
            String rawAuthority = uri.getRawAuthority();
            String path = uri.getPath() == null ? "" : uri.getPath();
            String lower = candidate.toLowerCase(Locale.ROOT);

            if (host == null || host.trim().isEmpty()) {
                findings.add("URL host could not be parsed");
                return findings;
            }

            if (IPV4.matcher(host).matches()) {
                findings.add("Website uses an IPv4 address instead of a domain name");
            }

            if (rawAuthority != null && rawAuthority.contains("@")) {
                findings.add("URL contains an @ symbol in its authority section");
            }

            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                findings.add("URL does not use HTTPS");
            }

            String[] labels = host.split("\\.");
            if (labels.length > 4) {
                findings.add("URL contains an unusually large number of domain labels");
            }

            if (candidate.length() > 100) {
                findings.add("URL is unusually long (over 100 characters)");
            }

            if (SHORTENERS.contains(host.toLowerCase(Locale.ROOT))) {
                findings.add("URL uses a recognized URL-shortening domain");
            }

            for (String word : SUSPICIOUS_PATH_WORDS) {
                if (path.toLowerCase(Locale.ROOT).contains(word)) {
                    findings.add("URL path contains login/verification-related word: " + word);
                    break;
                }
            }

            if (lower.contains("%00") || lower.contains("%0d") || lower.contains("%0a")) {
                findings.add("URL contains unusual encoded control characters");
            }

        } catch (URISyntaxException ex) {
            findings.add("URL format is invalid or could not be parsed");
        }

        return findings;
    }
}
