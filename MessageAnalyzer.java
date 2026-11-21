import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Locale;

public class MessageAnalyzer implements Analyzer {
    private static final List<String> URGENCY = Arrays.asList(
        "urgent", "immediately", "act now", "limited time", "suspended", "blocked");
    private static final List<String> PRIZE = Arrays.asList(
        "won", "winner", "prize", "reward", "free gift", "congratulations");
    private static final List<String> CREDENTIALS = Arrays.asList(
        "password", "otp", "one-time password", "pin", "verify your account",
        "confirm your account", "bank details");
    private static final Pattern URL_PATTERN = Pattern.compile(
        "(?i)\\b((?:https?://|www\\.)[^\\s<>\"']+)");

    @Override
    public List<String> analyze(String input) {
        List<String> findings = new ArrayList<String>();
        if (input == null || input.trim().isEmpty()) {
            findings.add("Empty message input");
            return findings;
        }

        String lower = input.toLowerCase(Locale.ROOT);
        addMatches(lower, URGENCY, "Urgency-related language detected", findings);
        addMatches(lower, PRIZE, "Prize/reward-related language detected", findings);
        addMatches(lower, CREDENTIALS, "Credential or account-verification language detected", findings);

        Matcher matcher = URL_PATTERN.matcher(input);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        if (count > 0) {
            findings.add("Embedded URL detected (" + count + ")");
        }
        return findings;
    }

    private void addMatches(String text, List<String> words, String description,
                            List<String> findings) {
        for (String word : words) {
            if (text.contains(word)) {
                findings.add(description + " (matched: " + word + ")");
                break;
            }
        }
    }

    public List<String> extractUrls(String input) {
        List<String> urls = new ArrayList<String>();
        if (input == null) return urls;
        Matcher matcher = URL_PATTERN.matcher(input);
        while (matcher.find()) {
            String url = matcher.group(1);
            while (url.endsWith(".") || url.endsWith(",") || url.endsWith(")") ||
                   url.endsWith(";") || url.endsWith("!")) {
                url = url.substring(0, url.length() - 1);
            }
            urls.add(url);
        }
        return urls;
    }
}
