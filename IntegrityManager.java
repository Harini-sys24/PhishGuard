import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class IntegrityManager {
    private static final String KEY_FILE = "config/secret.key";
    private static final String HISTORY_FILE = "data/scan_history.txt";
    private static final String HMAC_FILE = "data/scan_history.hmac";

    public String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return toHex(bytes);
        } catch (Exception ex) {
            return "SHA-256 unavailable";
        }
    }

    public void ensureSecretKey() throws IOException {
        File keyFile = new File(KEY_FILE);
        if (keyFile.exists()) return;

        File parent = keyFile.getParentFile();
        if (parent != null) parent.mkdirs();

        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Files.write(Paths.get(KEY_FILE), Base64.getEncoder().encode(key));
    }

    private byte[] readKey() throws IOException {
        ensureSecretKey();
        byte[] encoded = Files.readAllBytes(Paths.get(KEY_FILE));
        return Base64.getDecoder().decode(new String(encoded, StandardCharsets.UTF_8).trim());
    }

    public String hmacForFile(String filePath) throws Exception {
        ensureSecretKey();
        byte[] data;
        File file = new File(filePath);
        if (!file.exists()) data = new byte[0];
        else data = Files.readAllBytes(file.toPath());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(readKey(), "HmacSHA256"));
        return toHex(mac.doFinal(data));
    }

    public void updateHistoryHmac() throws Exception {
        String hmac = hmacForFile(HISTORY_FILE);
        Files.write(Paths.get(HMAC_FILE), hmac.getBytes(StandardCharsets.UTF_8));
    }

    public boolean verifyHistoryHmac() throws Exception {
        File stored = new File(HMAC_FILE);
        if (!stored.exists()) {
            updateHistoryHmac();
            return true; // First run: create a baseline authentication code.
        }
        String expected = new String(Files.readAllBytes(stored.toPath()),
                                     StandardCharsets.UTF_8).trim();
        String actual = hmacForFile(HISTORY_FILE);
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                                     actual.getBytes(StandardCharsets.UTF_8));
    }

    private String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) result.append(String.format("%02x", b & 0xff));
        return result.toString();
    }
}
