import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class ScanResult {
    private final String type;
    private final String input;
    private final List<String> indicators;
    private final int riskScore;
    private final String classification;
    private final String timestamp;
    private final String sha256;

    public ScanResult(String type, String input, List<String> indicators,
                      int riskScore, String classification, String sha256) {
        this.type = type;
        this.input = input;
        this.indicators = new ArrayList<String>(indicators);
        this.riskScore = riskScore;
        this.classification = classification;
        this.sha256 = sha256;
        this.timestamp = LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public String getType() { return type; }
    public String getInput() { return input; }
    public List<String> getIndicators() { return new ArrayList<String>(indicators); }
    public int getRiskScore() { return riskScore; }
    public String getClassification() { return classification; }
    public String getTimestamp() { return timestamp; }
    public String getSha256() { return sha256; }

    public String toHistoryLine() {
        // Base64 encoding keeps separators/newlines in user input from breaking the record.
        String encodedInput = java.util.Base64.getEncoder().encodeToString(
            input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return timestamp + "|" + type + "|" + riskScore + "|" +
               classification + "|" + sha256 + "|" + encodedInput;
    }

    public static ScanResult fromHistoryLine(String line) {
        // History is displayed as raw records by ReportManager; this method is reserved
        // for future structured history loading.
        return null;
    }

    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append("\n========================================\n");
        out.append("             PHISHGUARD REPORT\n");
        out.append("========================================\n");
        out.append("Type: ").append(type).append("\n");
        out.append("Input: ").append(input).append("\n");
        out.append("Timestamp: ").append(timestamp).append("\n\n");
        out.append("Detected indicators:\n");
        if (indicators.isEmpty()) {
            out.append("  No predefined suspicious indicators found.\n");
        } else {
            for (String indicator : indicators) {
                out.append("  [!] ").append(indicator).append("\n");
            }
        }
        out.append("\nRisk Score: ").append(riskScore).append("/100\n");
        out.append("Classification: ").append(classification).append("\n");
        out.append("SHA-256: ").append(sha256).append("\n");
        out.append("Recommendation: ");
        if ("HIGH RISK".equals(classification)) {
            out.append("Do not enter sensitive information. Verify the source independently.\n");
        } else if ("MEDIUM RISK".equals(classification)) {
            out.append("Review the indicators and verify the sender or website independently.\n");
        } else {
            out.append("No major predefined indicators were found; this does not guarantee safety.\n");
        }
        out.append("========================================\n");
        return out.toString();
    }
}
