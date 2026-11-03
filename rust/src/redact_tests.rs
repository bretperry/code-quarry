//! Fake secrets, assembled at run time so secret scanners don't flag this file.
use super::*;

fn fake(prefix: &str, body_len: usize) -> String {
    let alphabet = b"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7";
    let body: String = (0..body_len).map(|i| alphabet[(i * 7 + 3) % alphabet.len()] as char).collect();
    format!("{prefix}{body}")
}

fn assert_gone(input: &str, secret: &str) {
    let out = clean(input).expect("clean returned None");
    assert!(!out.contains(secret), "leaked {secret:?} from {input:?}: {out:?}");
    assert!(out.contains(MARK), "nothing redacted in {out:?}");
}

fn assert_kept(input: &str) {
    assert_eq!(clean(input).expect("clean returned None"), input);
}

#[test]
fn known_token_formats() {
    let cases = [
        format!("{}{}", "AKIA", "QWERTYUIOPASDFGH"),
        fake(&["gh", "p_"].concat(), 36),
        fake(&["github", "_pat_"].concat(), 60),
        fake(&["gl", "pat-"].concat(), 20),
        fake(&["xo", "xb-"].concat(), 40),
        fake(&["sk", "_live_"].concat(), 24),
        fake(&["sk", "_test_"].concat(), 24),
        fake(&["wh", "sec_"].concat(), 30),
        fake(&["sk-", "ant-"].concat(), 60),
        fake(&["sk-", "proj-"].concat(), 60),
        fake("sk-", 40),
        fake(&["AI", "za"].concat(), 35),
        fake(&["np", "m_"].concat(), 36),
        fake(&["py", "pi-"].concat(), 60),
        fake(&["h", "f_"].concat(), 34),
        fake(&["SG", "."].concat(), 22) + "." + &fake("", 43),
        fake(&["sh", "pat_"].concat(), 32),
        format!("{}.{}.{}", fake("eyJ", 20), fake("eyJ", 30), fake("", 40)),
        format!("123456789:{}", fake("AA", 33)),
    ];
    for secret in &cases {
        for wrap in [format!("x = {secret}\n"), format!("call(\"{secret}\")"), format!("see {secret}.")] {
            assert_gone(&wrap, secret);
        }
    }
}

#[test]
fn token_inside_a_url_or_after_equals() {
    let t = fake(&["gh", "p_"].concat(), 36);
    assert_gone(&format!("fetch('https://example.com/{t}/x')"), &t);
    assert_gone(&format!("--flag={t}"), &t);
}

#[test]
fn slack_webhook_url() {
    let url = format!("hooks.slack.com/services/T0000/B0000/{}", fake("", 24));
    assert_gone(&format!("post(\"https://{url}\")"), &url);
}

#[test]
fn high_entropy_strings() {
    for secret in ["Zx9Kq2Lm8Pw4Rt7Vb1Nc6Yh3Js5Df0Gu", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"] {
        assert_gone(&format!("const v = \"{secret}\";"), secret);
        assert!(looks_random(secret), "{secret}");
    }
}

#[test]
fn aws_secret_key_shape() {
    let secret = ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat();
    assert_gone(&format!("x = \"{secret}\""), &secret);
}

#[test]
fn private_key_blocks_keep_line_count() {
    let body = fake("", 64);
    let pem = format!("-----BEGIN RSA {k}-----\n{body}\n{body}\n-----END RSA {k}-----", k = ["PRIVATE", " KEY"].concat());
    let input = format!("a = 1\nkey = \"\"\"{pem}\"\"\"\nb = 2\n");
    let out = clean(&input).unwrap();
    assert!(!out.contains(&body) && !out.contains("BEGIN"), "{out}");
    assert_eq!(out.lines().count(), input.lines().count());
    assert!(out.contains("b = 2"));
}

#[test]
fn cut_off_private_key_is_removed_to_the_end() {
    let body = fake("", 40);
    let input = format!("-----BEGIN {}-----\n{body}\nmore", ["OPENSSH PRIVATE", " KEY"].concat());
    assert_gone(&input, &body);
}

#[test]
fn escaped_newline_private_key() {
    let body = fake("", 40);
    let input = format!("k = \"-----BEGIN {k}-----\\n{body}\\n-----END {k}-----\\n\"", k = ["PRIVATE", " KEY"].concat());
    assert_gone(&input, &body);
}

#[test]
fn credentials_in_urls() {
    assert_gone("db = 'postgres://admin:hunter2@db.example.com:5432/app'", "hunter2");
    assert_gone("redis://:hunter2@cache:6379", "hunter2");
    assert_gone("git clone https://x-token:abc@github.com/a/b", "abc@");
    assert_gone("url = \"https://api.example.com/v1?user=1&api_key=hunter2&x=2\"", "hunter2");
    let out = clean("https://api.example.com/v1?user=1&token=hunter2&x=2").unwrap();
    assert!(out.contains("user=1") && out.contains("x=2"), "{out}");
}

#[test]
fn assignments_with_sensitive_names() {
    for line in [
        "password = \"hunter\"",
        "PASSWORD = 'hunter'",
        "db_password: \"hunter\"",
        "dbPassword := \"hunter\"",
        "\"password\": \"hunter\",",
        "env[\"API_KEY\"] = \"hunter\"",
        "headers['Authorization'] = 'hunter'",
        "client_secret => 'hunter'",
        "const apiKey = `hunter`;",
        "const API_KEY: &str = \"hunter\";",
        "let token: string = 'hunter';",
        "var authToken string = \"hunter\"",
        "private_key = b\"hunter\"",
        "os.Setenv(\"AWS_SECRET_ACCESS_KEY\", \"hunter\")",
        "login(password=\"hunter\")",
        "setPassword(\"hunter\")",
        "--password hunter",
        "--password=\"hunter\"",
        "API_KEY=hunter",
        "export SECRET_KEY=hunter",
        "password = hunter2",
        "\"\"\"\npassword: hunter2\n\"\"\"",
        "AccountKey=hunter2;",
        "if password == \"hunter\":",
        "password =\n    \"hunter\"",
    ] {
        assert_gone(line, "hunter");
    }
}

#[test]
fn literals_wrapped_in_calls_and_fallbacks() {
    for line in [
        "password: Some(\"hunter\".into())",
        "password = Field(default=\"hunter\")",
        "Password: []byte(\"hunter\"),",
        "SecretAccessKey: aws.String(\"hunter\"),",
        "const secret = Buffer.from('hunter');",
        "let token = String::from(\"hunter\");",
        "const secret = process.env.S || 'hunter';",
        "const token = process.env.T ?? \"hunter\";",
        "secret ||= 'hunter'",
        "let pw = env.unwrap_or(\"hunter\");",
        "password = os.getenv(\"A\", \"hunter\")",
        "req.SetBasicAuth(\"bob\", \"hunter\")",
        "client.basic_auth(\"bob\", Some(\"hunter\"))",
        "new Credentials(\"bob\", \"hunter\")",
        "user, pass := \"bob\", \"hunter\"",
        "click.option(\"--password\", default=\"hunter\")",
        "parser.add_argument('--api-key', default='hunter')",
        "`json:\"password\" default:\"hunter\"`",
        "@ConfigProperty(name=\"db.password\", defaultValue=\"hunter\")",
        "password: z.string().default(\"hunter\"),",
        "let password = r#\"hunter\"#;",
    ] {
        assert_gone(line, "hunter");
    }
}

#[test]
fn escaped_json_in_a_string() {
    assert_gone("body := \"{\\\"password\\\":\\\"hunter\\\"}\"", "hunter");
    assert_gone("String b = \"{\\\"api_key\\\": \\\"hunter\\\", \\\"a\\\": 1}\";", "hunter");
}

#[test]
fn unquoted_values_inside_strings() {
    for line in ["\"Server=x;Pwd=a.b2;\"", "\"Password=$x1;\"", "\"Password=!hunter;\"", "curl -u bob:hunter2 x", "\"bob:hunter@tcp(db:3306)/app\"", "\"//bob:hunter@host/db\""] {
        assert_gone(line, "hunter");
    }
    assert_gone("\"Server=x;Pwd=a.b2;\"", "a.b2");
    assert_gone("\"Password=$x1;\"", "$x1");
}

#[test]
fn more_sensitive_names() {
    for name in ["passwords", "dbpassword", "clientsecret", "jwtKey", "hmacKey", "appKey", "salt", "pin", "passcode", "pw"] {
        assert_gone(&format!("{name} = \"hunter\""), "hunter");
    }
}

#[test]
fn random_strings_without_mixed_case() {
    for secret in [
        "k7d9x2mq8vz4tj1pn6wr3bh5",
        "qhzvxkwjtnbfgpmdyrcsloue",
        "550e8400-e29b-41d4-a716-446655440000",
        "9f86d081884c7d659a2feaa0",
    ] {
        assert_gone(&format!("v = \"{secret}\""), secret);
    }
}

#[test]
fn generated_passwords_with_symbols() {
    assert_gone("v = \"xK9!mQ2@pL5#vR8$wT\"", "xK9");
    assert_gone("v = \"a1.B2:c3.D4:e5.F6:g7\"", "a1.B2");
}

#[test]
fn a_long_value_is_removed_whole() {
    let long = format!("password = \"{}\u{e9}{}\"", "a".repeat(9000), "tail");
    let out = clean(&long).unwrap();
    assert!(!out.contains("tail"), "{}", out.len());
}

#[test]
fn authorization_schemes() {
    assert_gone("Authorization: Bearer abc123def456", "abc123def456");
    assert_gone("curl -H 'Authorization: Basic dXNlcjpwYXNz=' x", "dXNlcjpwYXNz");
}

#[test]
fn ordinary_code_is_left_alone() {
    for line in [
        "token = get_token(request)",
        "const secret = process.env.SECRET;",
        "fn check(password: &str) -> bool {",
        "let token: Option<String> = None;",
        "password: string,",
        "token: u32,",
        "auth = self.auth",
        "if token is None:",
        "max_tokens = 100",
        "tokens = text.split()",
        "tokenizer = load(\"bert\")",
        "author = \"Ada\"",
        "bypass = \"yes\"",
        "pass",
        "os.getenv(\"API_KEY\")",
        "export PASSWORD=$OTHER",
        "getUserAccountSettingsFromDatabase(accountId)",
        "import { something } from '../../shared/lib/components/some-long-file-name';",
        "basic authentication is required",
        "the bearer token goes in a header",
        "const color = \"#ff00aa\";",
        "see https://example.com/a/b?page=2&sort=name",
        "user@example.com",
        "x = 12345678901234567890123456",
        "auth.get(\"/login\", handler)",
        "password = args.password",
        "login(password=args.pw)",
    ] {
        assert_kept(line);
    }
}

#[test]
fn non_ascii_text_survives() {
    assert_kept("// caf\u{e9} \u{2603} \u{1f600} ok");
    assert_gone("password = \"caf\u{e9}\u{1f600}\" // \u{2603}", "caf");
}

#[test]
fn clean_is_stable_on_its_own_output() {
    let input = format!("password = \"hunter\"\nx = {}\n", fake(&["gh", "p_"].concat(), 36));
    let once = clean(&input).unwrap();
    assert_eq!(clean(&once).unwrap(), once);
}

#[test]
fn line_count_is_preserved() {
    let input = "a\npassword = \"\"\"one\ntwo\nthree\"\"\"\nb\n";
    let out = clean(input).unwrap();
    assert_eq!(out.matches('\n').count(), input.matches('\n').count());
    assert!(out.ends_with("\nb\n"));
}

#[test]
fn a_panic_withholds() {
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let got: Option<String> = guarded(|| panic!("boom"));
    std::panic::set_hook(quiet);
    assert_eq!(got, None);
}

#[test]
fn sensitive_paths() {
    for p in [
        ".env", ".env.local", "app/.env.production", "prod.env", "secrets.py", "config/secrets.ts", "app/credentials.js",
        "secrets/db.py", ".ssh/config.py", ".aws/credentials", "server.pem", "tls/server.key", "id_rsa", "id_ed25519",
        ".npmrc", ".netrc", ".pypirc", "service-account.json", "my_service_account.py", "x.tfvars", "api_keys.go",
        "../outside.py", "PASSWORDS.ts", "secret/a.py", "keys/a.py", "private/a.py", "vault/a.py", ".env/a.py", ".config/gcloud/a.py",
    ] {
        assert!(is_sensitive_path(p), "{p}");
    }
    for p in ["src/main.rs", "app/config.py", "lib/auth.ts", "tokenizer.py", "key_value.go", "environment.js", "docs/enviro.py"] {
        assert!(!is_sensitive_path(p), "{p}");
    }
}
