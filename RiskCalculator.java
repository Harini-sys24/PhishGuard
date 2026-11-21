import java.util.List;

public class RiskCalculator {
    public int calculateURLRisk(List<String> indicators) {
        int score = 0;
        for (String item : indicators) {
            if (item.contains("IPv4 address")) score += 25;
            else if (item.contains("@ symbol")) score += 20;
            else if (item.contains("shortening")) score += 10;
            else if (item.contains("domain labels")) score += 15;
            else if (item.contains("login/verification")) score += 10;
            else if (item.contains("unusually long")) score += 10;
            else if (item.contains("HTTPS")) score += 5;
            else if (item.contains("invalid") || item.contains("could not be parsed")) score += 10;
            else score += 5;
        }
        return Math.min(score, 100);
    }

    public int calculateMessageRisk(List<String> indicators) {
        int score = 0;
        for (String item : indicators) {
            if (item.contains("Credential")) score += 25;
            else if (item.contains("Urgency")) score += 15;
            else if (item.contains("Prize")) score += 10;
            else if (item.contains("Embedded URL")) score += 10;
            else score += 5;
        }
        return Math.min(score, 100);
    }

    public String classify(int score) {
        if (score >= 60) return "HIGH RISK";
        if (score >= 30) return "MEDIUM RISK";
        return "LOW RISK";
    }
}
