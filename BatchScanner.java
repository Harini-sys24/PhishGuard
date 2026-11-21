import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class BatchScanner {
    private final ThreatDetector detector = new ThreatDetector();

    public List<ScanResult> scanFile(String filePath)
            throws IOException, InterruptedException, ExecutionException {
        List<String> urls = Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        List<Future<ScanResult>> futures = new ArrayList<Future<ScanResult>>();

        try {
            for (final String url : urls) {
                if (url.trim().isEmpty() || url.trim().startsWith("#")) continue;
                futures.add(executor.submit(new Callable<ScanResult>() {
                    public ScanResult call() {
                        return detector.scanURLForBatch(url.trim());
                    }
                }));
            }

            List<ScanResult> results = new ArrayList<ScanResult>();
            for (Future<ScanResult> future : futures) {
                results.add(future.get());
            }
            return results;
        } finally {
            executor.shutdown();
        }
    }
}
