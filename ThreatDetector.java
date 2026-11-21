import java.util.ArrayList;
import java.util.List;

public class ThreatDetector {
    private final URLAnalyzer urlAnalyzer;
    private final MessageAnalyzer messageAnalyzer;
    private final RiskCalculator riskCalculator;
    private final IntegrityManager integrityManager;

    public ThreatDetector() {
        urlAnalyzer = new URLAnalyzer();
        messageAnalyzer = new MessageAnalyzer();
        riskCalculator = new RiskCalculator();
        integrityManager = new IntegrityManager();
    }

    public ScanResult scanURL(String input) {
        List<String> indicators = urlAnalyzer.analyze(input);
        int score = riskCalculator.calculateURLRisk(indicators);
        String hash = integrityManager.sha256(input == null ? "" : input);
        return new ScanResult("URL", input, indicators, score,
                              riskCalculator.classify(score), hash);
    }

    public ScanResult scanMessage(String input) {
        List<String> indicators = messageAnalyzer.analyze(input);
        List<String> allIndicators = new ArrayList<String>(indicators);

        for (String url : messageAnalyzer.extractUrls(input)) {
            List<String> urlFindings = urlAnalyzer.analyze(url);
            for (String finding : urlFindings) {
                allIndicators.add("Embedded URL: " + finding);
            }
        }

        int score = riskCalculator.calculateMessageRisk(allIndicators);
        String hash = integrityManager.sha256(input == null ? "" : input);
        return new ScanResult("MESSAGE", input, allIndicators, score,
                              riskCalculator.classify(score), hash);
    }

    public ScanResult scanURLForBatch(String input) {
        return scanURL(input);
    }
}
