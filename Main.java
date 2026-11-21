import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;

public class Main {
    private static final Scanner INPUT = new Scanner(System.in);
    private static final ThreatDetector detector = new ThreatDetector();
    private static final ReportManager reports = new ReportManager();
    private static final BatchScanner batchScanner = new BatchScanner();

    public static void main(String[] args) {
        new File("data").mkdirs();
        new File("reports").mkdirs();
        new File("config").mkdirs();

        System.out.println("========================================");
        System.out.println("              PHISHGUARD");
        System.out.println("   Explainable Phishing Threat Analyzer");
        System.out.println("========================================");

        boolean running = true;
        while (running) {
            displayMenu();
            int choice = readChoice();
            try {
                switch (choice) {
                    case 1: scanURL(); break;
                    case 2: scanMessage(); break;
                    case 3: scanBatch(); break;
                    case 4: reports.showHistory(); break;
                    case 5: reports.verifyIntegrity(); break;
                    case 6:
                        running = false;
                        System.out.println("Thank you for using PHISHGUARD. Stay alert. Stay secure.");
                        break;
                    default:
                        System.out.println("Please enter a number from 1 to 6.");
                }
            } catch (Exception ex) {
                System.out.println("Operation could not be completed: " + ex.getMessage());
            }
        }
    }

    private static void displayMenu() {
        System.out.println("\n1. Scan a URL");
        System.out.println("2. Scan an Email / SMS Message");
        System.out.println("3. Scan Multiple URLs from a File");
        System.out.println("4. View Scan History");
        System.out.println("5. Verify Audit Log Integrity");
        System.out.println("6. Exit");
        System.out.print("Enter your choice: ");
    }

    private static int readChoice() {
        String value = INPUT.nextLine().trim();
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static void scanURL() throws Exception {
        System.out.print("Enter URL to analyze: ");
        String url = INPUT.nextLine().trim();
        if (url.isEmpty()) {
            System.out.println("URL cannot be empty.");
            return;
        }
        ScanResult result = detector.scanURL(url);
        System.out.println(result);
        reports.saveResult(result);
        System.out.println("Report and history saved.");
    }

    private static void scanMessage() throws Exception {
        System.out.println("Enter message (finish by pressing Enter on an empty line):");
        StringBuilder message = new StringBuilder();
        while (true) {
            String line = INPUT.nextLine();
            if (line.trim().isEmpty()) break;
            if (message.length() > 0) message.append('\n');
            message.append(line);
        }
        if (message.length() == 0) {
            System.out.println("Message cannot be empty.");
            return;
        }
        ScanResult result = detector.scanMessage(message.toString());
        System.out.println(result);
        reports.saveResult(result);
        System.out.println("Report and history saved.");
    }

    private static void scanBatch() throws Exception {
        System.out.print("Enter path to a text file containing URLs: ");
        String path = INPUT.nextLine().trim();
        if (path.isEmpty() || !Files.exists(Paths.get(path))) {
            System.out.println("File not found. Create a text file with one URL per line.");
            return;
        }

        List<ScanResult> results = batchScanner.scanFile(path);
        int low = 0, medium = 0, high = 0;
        System.out.println("\n========== BATCH SCAN REPORT ==========");
        for (ScanResult result : results) {
            System.out.println(result.getInput() + " -> " +
                               result.getRiskScore() + "/100 " +
                               result.getClassification());
            reports.saveResult(result);
            if ("LOW RISK".equals(result.getClassification())) low++;
            else if ("MEDIUM RISK".equals(result.getClassification())) medium++;
            else high++;
        }
        System.out.println("--------------------------------------");
        System.out.println("Total scanned: " + results.size());
        System.out.println("Low: " + low + " | Medium: " + medium + " | High: " + high);
        System.out.println("======================================");
    }
}
