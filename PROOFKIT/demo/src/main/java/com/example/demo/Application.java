package com.example.demo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
@EnableJpaRepositories(considerNestedRepositories = true)
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    static String clip(String s, int max) {
        if (s == null) return "";
        s = s.trim();
        return s.length() > max ? s.substring(0, max) : s;
    }

    /* ================= Entities + Repositories ================= */

    @Entity
    @Table(name = "scam_reports")
    public static class ScamReport {
        @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        public Long id;
        @Column(length = 200) public String title;
        @Column(length = 200) public String company;
        @Column(length = 300) public String contact;
        @Column(length = 1000) public String description;
        @Column(length = 100) public String category;
        public int reports = 1;
        public Date createdAt = new Date();

        public ScamReport() {}
        public ScamReport(String title, String company, String contact, String description, String category, int reports) {
            this.title = title; this.company = company; this.contact = contact;
            this.description = description; this.category = category; this.reports = reports;
        }
    }

    public interface ScamRepo extends JpaRepository<ScamReport, Long> {
        Optional<ScamReport> findFirstByCompanyIgnoreCaseAndContactIgnoreCase(String company, String contact);
    }

    @Entity
    @Table(name = "app_users")
    public static class AppUser {
        @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        public Long id;
        @Column(length = 100, nullable = false) public String name;
        @Column(length = 200, nullable = false, unique = true) public String email;
        @Column(length = 100, nullable = false) public String passwordHash;
        public Date createdAt = new Date();
    }

    public interface UserRepo extends JpaRepository<AppUser, Long> {
        Optional<AppUser> findByEmailIgnoreCase(String email);
    }

    /* ================= JWT token service ================= */

    @Component
    public static class TokenService {
        private final SecretKey key;

        public TokenService(@Value("${app.jwt.secret}") String secret) {
            this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }

        public String create(AppUser u) {
            Date now = new Date();
            return Jwts.builder()
                .subject(String.valueOf(u.id))
                .claim("email", u.email)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + 7L * 24 * 3600 * 1000)) // 7 days
                .signWith(key)
                .compact();
        }

        /** Returns the user id, or null if the token is invalid or expired. */
        public Long verify(String token) {
            try {
                String sub = Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(token).getPayload().getSubject();
                return Long.parseLong(sub);
            } catch (Exception e) {
                return null;
            }
        }
    }

    /* ================= Seed sample data ================= */

    @Bean
    CommandLineRunner seed(ScamRepo repo) {
        return args -> {
            if (repo.count() > 0) return;
            repo.saveAll(List.of(
                new ScamReport("Fake internship fee", "TechNova Solutions (sample)", "+91 90000 00001", "Registration fee before joining", "Internship", 128),
                new ScamReport("Work-from-home typing job", "QuickEarn Hub (sample)", "earnfast-jobs.example", "Pay a kit deposit to start", "Work from home", 94),
                new ScamReport("Fake HR offer letter", "Global Infotech Ltd (sample)", "hr.globalinfotech@gmail.example", "Offer with no interview, asks for Aadhaar", "Offer letter", 61),
                new ScamReport("Telegram task scam", "DailyTasks India (sample)", "t.me/example-tasks", "Small tasks, then asks you to deposit", "Payment fraud", 203),
                new ScamReport("Visa and abroad job", "SkyHire Abroad (sample)", "+91 90000 00002", "Guaranteed overseas job for a fee", "Recruitment", 47),
                new ScamReport("Fake bank KYC job call", "SecureBank Careers (sample)", "+91 90000 00003", "Asks for OTP to 'confirm your job'", "Payment fraud", 89)
            ));
        };
    }

    /* ================= DTOs ================= */

    public record Flag(String title, String why, String evidence) {}
    public record Result(int score, String cls, List<Flag> flags, String company, String domain, String summary) {}

    /* ================= Analysis engine ================= */

    static final int CI = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;

    record Rule(String title, int weight, Pattern re, String why) {}

    static final List<Rule> RULES = List.of(
        new Rule("Upfront payment requested", 35, Pattern.compile(
            "(registration|processing|security|training|kit|refundable)?\\s*(fee|deposit|charges?)[^.\\n]{0,40}(₹|rs\\.?|inr)\\s?[\\d,]+"
            + "|(₹|rs\\.?|inr)\\s?[\\d,]+[^.\\n]{0,40}(fee|deposit|charges?)"
            + "|\\bpay\\b[^.\\n]{0,30}(₹|rs\\.?|inr)", CI),
            "Genuine employers do not charge candidates to hire or train them."),
        new Rule("Unofficial email address", 20, Pattern.compile(
            "[\\w.+-]+@(gmail|yahoo|outlook|hotmail|rediffmail)\\.\\w+", CI),
            "Real recruiters normally write from a company domain, not a free email service."),
        new Rule("Urgent deadline pressure", 15, Pattern.compile(
            "(within|in)\\s+\\d+\\s*(hours?|hrs?|minutes?)|immediately|urgent|last chance|today only|limited (seats|slots)", CI),
            "Pressure to act fast stops you from checking. Scammers rely on this."),
        new Rule("Chat-app only contact", 10, Pattern.compile(
            "telegram|whatsapp|t\\.me/", CI),
            "Moving to chat apps keeps the conversation off official channels."),
        new Rule("Unrealistic pay or guarantees", 10, Pattern.compile(
            "guaranteed|no interview|without interview|₹\\s?\\d{2,3},?\\d{3}\\s*(per|/)\\s*(day|week)"
            + "|earn\\s+(₹|rs\\.?)\\s?[\\d,]+\\s*(per|/)\\s*day|work from home", CI),
            "Very high pay for little effort, or no interview, is a classic bait."),
        new Rule("Sensitive documents requested early", 10, Pattern.compile(
            "aadhaar|aadhar|pan card|bank (account|details)|otp|passport", CI),
            "Sharing ID or bank details before a verified offer risks identity theft.")
    );

    static final Map<String, String> BRANDS = new LinkedHashMap<>();
    static {
        BRANDS.put("infosys", "infosys.com"); BRANDS.put("tcs", "tcs.com"); BRANDS.put("wipro", "wipro.com");
        BRANDS.put("accenture", "accenture.com"); BRANDS.put("google", "google.com"); BRANDS.put("amazon", "amazon.com");
        BRANDS.put("cognizant", "cognizant.com"); BRANDS.put("capgemini", "capgemini.com");
        BRANDS.put("deloitte", "deloitte.com"); BRANDS.put("flipkart", "flipkart.com"); BRANDS.put("zomato", "zomato.com");
    }

    static final Pattern EMAIL = Pattern.compile("[\\w.+-]+@([\\w-]+\\.[\\w.]+)");
    static final Pattern COMPANY = Pattern.compile("\\b(?:at|with|from|join)\\s+([A-Z][\\w&]+(?:\\s[A-Z][\\w&]+){0,3})");
    static final Pattern SELECTED = Pattern.compile("congratulations[^.!]*|you (are|have been) selected[^.!]*", CI);

    static String classify(int score) {
        return score >= 60 ? "LIKELY SCAM" : score >= 30 ? "SUSPICIOUS" : "NO STRONG RED FLAGS";
    }

    static Result analyzeText(String text) {
        List<Flag> flags = new ArrayList<>();
        int score = 0;

        for (Rule r : RULES) {
            Matcher m = r.re().matcher(text);
            if (m.find()) {
                flags.add(new Flag(r.title(), r.why(), m.group().trim()));
                score += r.weight();
            }
        }

        if (SELECTED.matcher(text).find() && !Pattern.compile("interview", CI).matcher(text).find()) {
            Matcher m = SELECTED.matcher(text);
            String ev = m.find() ? m.group() : "";
            flags.add(new Flag("Selected without an interview",
                "A genuine offer almost always follows an interview or assessment.", ev));
            score += 10;
        }

        Matcher em = EMAIL.matcher(text);
        String domain = em.find() ? em.group(1) : "";

        if (!domain.isEmpty()) {
            for (var b : BRANDS.entrySet()) {
                boolean named = Pattern.compile("\\b" + b.getKey() + "\\b", CI).matcher(text).find();
                if (named && !domain.toLowerCase().endsWith(b.getValue())) {
                    flags.add(new Flag("Possible brand impersonation",
                        "The offer names " + b.getKey() + " but the email domain is not its official domain (" + b.getValue() + ").",
                        domain));
                    score += 25;
                    break;
                }
            }
        }

        score = Math.min(score, 100);
        Matcher cm = COMPANY.matcher(text);
        String company = cm.find() ? cm.group(1) : "";

        String summary = flags.isEmpty()
            ? "Local checks found nothing unusual. That does not prove the offer is genuine. Verify the company on its official website."
            : flags.size() + " warning sign" + (flags.size() > 1 ? "s" : "")
              + " found by pattern checks. Do not pay or share documents until the company is verified independently.";

        return new Result(score, classify(score), flags, company, domain, summary);
    }

    static Result analyzeUrl(String raw) {
        URI u;
        try { u = new URI(raw.trim()); } catch (Exception e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid URL"); }
        String host = u.getHost();
        if (host == null || u.getScheme() == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid URL");

        List<Flag> flags = new ArrayList<>();
        int score = 0;

        if (!"https".equalsIgnoreCase(u.getScheme())) {
            flags.add(new Flag("Connection is not HTTPS", "Legitimate hiring sites protect candidate data with HTTPS.", u.getScheme() + ":"));
            score += 25;
        }
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            flags.add(new Flag("IP address instead of a domain name", "Companies rarely host careers pages on raw IP addresses.", host));
            score += 35;
        }
        if (Pattern.compile("\\.(xyz|top|click|work|buzz|tk|gq|ml)$", CI).matcher(host).find()) {
            flags.add(new Flag("Uncommon domain ending", "These endings are frequently used for throwaway scam sites.", host));
            score += 20;
        }
        if (Pattern.compile("bit\\.ly|tinyurl|t\\.co|cutt\\.ly|rb\\.gy", CI).matcher(host).find()) {
            flags.add(new Flag("Shortened link hides the destination", "You cannot see where it leads before clicking.", host));
            score += 25;
        }
        if (host.chars().filter(c -> c == '-').count() >= 3) {
            flags.add(new Flag("Many hyphens in the domain", "Look-alike domains often chain several words with hyphens.", host));
            score += 15;
        }
        score = Math.min(score, 100);
        return new Result(score, classify(score), flags, "", host,
            "URL structure checked. Domain age, ownership and page content were not inspected.");
    }

    /* ================= Auth Controller ================= */

    @RestController
    @RequestMapping("/api/auth")
    @CrossOrigin(origins = "*")
    public static class AuthController {

        private final UserRepo users;
        private final TokenService tokens;
        private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        public AuthController(UserRepo users, TokenService tokens) {
            this.users = users;
            this.tokens = tokens;
        }

        private Map<String, Object> authResponse(AppUser u) {
            Map<String, Object> user = new LinkedHashMap<>();
            user.put("id", u.id);
            user.put("name", u.name);
            user.put("email", u.email);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("token", tokens.create(u));
            out.put("user", user);
            return out;
        }

        @PostMapping("/register")
        public Map<String, Object> register(@RequestBody Map<String, String> b) {
            String name = clip(b.get("name"), 100);
            String email = clip(b.get("email"), 200).toLowerCase();
            String pw = b.get("password") == null ? "" : b.get("password");

            if (name.isBlank())
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name is required");
            if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter a valid email address");
            if (pw.length() < 6 || pw.length() > 72)
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be 6 to 72 characters");
            if (users.findByEmailIgnoreCase(email).isPresent())
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered. Please login.");

            AppUser u = new AppUser();
            u.name = name;
            u.email = email;
            u.passwordHash = encoder.encode(pw);
            users.save(u);
            return authResponse(u);
        }

        @PostMapping("/login")
        public Map<String, Object> login(@RequestBody Map<String, String> b) {
            String email = clip(b.get("email"), 200).toLowerCase();
            String pw = b.get("password") == null ? "" : b.get("password");

            AppUser u = users.findByEmailIgnoreCase(email).orElse(null);
            if (u == null || !encoder.matches(pw, u.passwordHash))
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
            return authResponse(u);
        }

        @GetMapping("/me")
        public Map<String, Object> me(@RequestHeader(value = "Authorization", defaultValue = "") String h) {
            if (!h.startsWith("Bearer "))
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token");
            Long id = tokens.verify(h.substring(7));
            AppUser u = id == null ? null : users.findById(id).orElse(null);
            if (u == null)
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            Map<String, Object> user = new LinkedHashMap<>();
            user.put("id", u.id);
            user.put("name", u.name);
            user.put("email", u.email);
            return user;
        }
    }

    /* ================= REST Controller ================= */

    @RestController
    @RequestMapping("/api")
    @CrossOrigin(origins = "*")
    public static class ApiController {

        private final ScamRepo repo;
        public ApiController(ScamRepo repo) { this.repo = repo; }

        @PostMapping("/analyze")
        public Result analyze(@RequestBody Map<String, String> body) {
            String text = body.getOrDefault("text", "");
            if (text.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "text is required");
            if (text.length() > 3000) text = text.substring(0, 3000);
            return analyzeText(text);
        }

        @PostMapping(value = "/analyze/document", consumes = "multipart/form-data")
        public Result analyzeDocument(@RequestParam("file") MultipartFile file) throws Exception {
            String name = Optional.ofNullable(file.getOriginalFilename()).orElse("").toLowerCase();
            if (!name.endsWith(".pdf")) {
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Only PDF text extraction is supported on the server");
            }
            try (PDDocument doc = PDDocument.load(file.getBytes())) {
                PDFTextStripper s = new PDFTextStripper();
                s.setEndPage(4);
                String text = s.getText(doc).trim();
                if (text.length() < 20) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "No readable text");
                return analyzeText(text.length() > 3000 ? text.substring(0, 3000) : text);
            }
        }

        @PostMapping("/analyze/url")
        public Result analyzeUrlEndpoint(@RequestBody Map<String, String> body) {
            return analyzeUrl(body.getOrDefault("url", ""));
        }

        @GetMapping("/companies/verify")
        public Map<String, Object> verify(@RequestParam(defaultValue = "") String name,
                                          @RequestParam(defaultValue = "") String domain) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            out.put("domain", domain);
            boolean free = domain.matches("(?i)^(gmail|yahoo|outlook|hotmail|rediffmail)\\..*");
            out.put("freeEmailDomain", free);
            Boolean resolves = null;
            if (!domain.isBlank() && !free) {
                try { InetAddress.getByName(domain); resolves = true; } catch (Exception e) { resolves = false; }
            }
            out.put("dnsResolves", resolves);
            return out;
        }

        @GetMapping("/scams")
        public List<Map<String, Object>> scams() {
            List<Map<String, Object>> list = new ArrayList<>();
            for (ScamReport r : repo.findAll()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("t", r.title);
                m.put("c", r.company);
                m.put("x", r.contact);
                m.put("d", r.description);
                m.put("k", r.category);
                m.put("n", r.reports);
                list.add(m);
            }
            list.sort((a, b) -> Integer.compare((int) b.get("n"), (int) a.get("n")));
            return list;
        }

        @PostMapping("/scams/report")
        public Map<String, Object> report(@RequestBody Map<String, String> b) {
            String type = clip(b.get("type"), 100), company = clip(b.get("company"), 200),
                   contact = clip(b.get("contact"), 300), desc = clip(b.get("description"), 1000);
            if (company.isBlank() || contact.isBlank() || desc.isBlank())
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "company, contact and description are required");

            ScamReport r = repo.findFirstByCompanyIgnoreCaseAndContactIgnoreCase(company, contact).orElse(null);
            if (r != null) r.reports++;
            else r = new ScamReport(type + " report", company, contact, desc, type, 1);
            repo.save(r);
            return Map.of("status", "ok", "id", r.id, "reports", r.reports);
        }
    }
}