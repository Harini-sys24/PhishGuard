import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class ReportManager {
    private static final String HISTORY_FILE = "data/scan_history.txt";
    private final IntegrityManager integrityManager = new IntegrityManager();

    public ReportManager() {
        new File("data").mkdirs();
        new File("reports").mkdirs();
    }

    public synchronized void saveResult(ScanResult result) throws Exception {
        Files.write(Paths.get(HISTORY_FILE),
            (result.toHistoryLine() + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        integrityManager.updateHistoryHmac();
        saveReport(result);
    }

    public void saveReport(ScanResult result) throws IOException {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS"));
        String safeType = result.getType().replaceAll("[^A-Za-z0-9]", "_");
        String path = "reports/" + safeType + "_" + stamp + ".txt";
        Files.write(Paths.get(path), result.toString().getBytes(StandardCharsets.UTF_8));
    }

    public void showHistory() throws IOException {
        File file = new File(HISTORY_FILE);
        System.out.println("\n========== SCAN HISTORY ==========");
        if (!file.exists() || file.length() == 0) {
            System.out.println("No scan history available.");
        } else {
            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            for (String line : lines) {
                String[] parts = line.split("\\|", 6);
                if (parts.length >= 5) {
                    System.out.println("Date: " + parts[0] + " | Type: " + parts[1] +
                        " | Score: " + parts[2] + " | Result: " + parts[3]);
                }
            }
        }
        System.out.println("==================================");
    }

    public void verifyIntegrity() {
        try {
            boolean valid = integrityManager.verifyHistoryHmac();
            if (valid) {
                System.out.println("INTEGRITY STATUS: VERIFIED");
                System.out.println("No modification detected since the last authenticated update.");
            } else {
                System.out.println("INTEGRITY STATUS: FAILED");
                System.out.println("The history file may have been modified.");
            }
        } catch (Exception ex) {
            System.out.println("Could not verify integrity: " + ex.getMessage());
        }
    }
}
