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

#[test]
fn yaml_values_under_a_secret_name_are_hidden_whole() {
    for (input, want) in [
        ("password: correct horse battery staple\n", "password: [REDACTED]\n"),
        ("  - db_password:    two words here  # note\n", "  - db_password:    [REDACTED]  # note\n"),
        ("\"api_key\": plain words\n", "\"api_key\": [REDACTED]\n"),
        ("password: hunter\n", "password: [REDACTED]\n"),
        ("private_key: |\n  line one\n\n  line two\nafter: ok\n", "private_key: |\n  [REDACTED]\n\n  [REDACTED]\nafter: ok\n"),
        ("tokens:\n  - one\n  - two words\nname: x\n", "tokens:\n  - [REDACTED]\n  - [REDACTED]\nname: x\n"),
        ("passwords:\n- one\nname: x\n", "passwords:\n- [REDACTED]\nname: x\n"),
    ] {
        assert_eq!(clean(input).unwrap(), want, "{input:?}");
    }
}

#[test]
fn code_that_looks_like_yaml_stays_readable() {
    for input in [
        "struct A {\n    password: String,\n}\n",
        "class B:\n    password: str\n    api_key: SecretStr\n    token: Optional[str]\n",
        "interface C {\n  token: string;\n}\n",
        "auth:\n  user: bob\n  method: basic\n",
        "const o = {\n  password: getPassword(),\n};\n",
        "password: ${DB_PASSWORD}\n",
    ] {
        assert_eq!(clean(input).unwrap(), input);
    }
}

#[test]
fn an_escaped_space_does_not_end_a_value() {
    assert_eq!(clean("PASSWORD=abc\\ def\\ LEAK\n").unwrap(), "PASSWORD=[REDACTED]\n");
    // An unquoted .env value runs to the end of its line.
    assert_eq!(clean("PASSWORD=abc\\ def more\n").unwrap(), "PASSWORD=[REDACTED]\n");
}

#[test]
fn xml_elements_under_a_secret_name_are_hidden() {
    assert_eq!(clean("<password>LEAK</password>\n").unwrap(), "<password>[REDACTED]</password>\n");
    assert_eq!(clean("<apiKey id=\"1\">LEAK two</apiKey>\n").unwrap(), "<apiKey id=\"1\">[REDACTED]</apiKey>\n");
    assert_eq!(clean("<password/>\n<name>x</name>\n").unwrap(), "<password/>\n<name>x</name>\n");
}

#[test]
fn arrays_under_a_secret_name_hide_every_literal() {
    assert_eq!(clean("secret = [\n \"LEAK\",\n]\nother = [\"fine\"]\n").unwrap(), "secret = [\n [REDACTED],\n]\nother = [\"fine\"]\n");
    assert_eq!(
        clean("{\"tokens\": [\n  \"A1\",\n  [\"B2\"]\n], \"x\": [\"ok\"]}\n").unwrap(),
        "{\"tokens\": [\n  [REDACTED],\n  [[REDACTED]]\n], \"x\": [\"ok\"]}\n"
    );
    assert_eq!(clean("tokens = [t for t in words]\n").unwrap(), "tokens = [t for t in words]\n");
}

#[test]
fn env_files_under_other_names_are_sensitive_and_templates_are_not() {
    for p in ["app.env.txt", "prod.env.bak", "backup.env.txt", ".dev.vars", "x/.dev.vars.production", ".env", "a/prod.env"] {
        assert!(is_sensitive_path(p), "{p}");
    }
    for p in [".env.example", ".env.local.sample", "app/.env.template", "environment.ts", "my.envelope.js"] {
        assert!(!is_sensitive_path(p), "{p}");
    }
    // A template suffix exempts only the .env rule.
    assert!(is_sensitive_path("secrets.json.example"));
}

// ---- QA round 2 ----

#[test]
fn generics_and_jsx_are_not_xml() {
    for input in [
        "fn peek() -> Option<Token> {\n    let a = 1;\n    let b = 2;\n}\n",
        "let v: Vec<Token> = Vec::new();\nlet n = 3;\n",
        "struct A { s: Arc<Secret> }\nfn f() {}\n",
        "fn load() -> Result<Credentials, E> {\n    todo!()\n}\n",
        "<PasswordInput onChange={(e) => set(e)} />\n<div>hello</div>\n",
        "/// Parses an `<ident-token>`.\nfn parse() {}\n",
        "<password>\n  multi\n</password>\n",
    ] {
        assert_kept(input);
    }
    assert_eq!(clean("<password>LEAK</password>\n").unwrap(), "<password>[REDACTED]</password>\n");
    assert_eq!(clean("<Token>LEAK</Token> <b>x</b>\n").unwrap(), "<Token>[REDACTED]</Token> <b>x</b>\n");
}

#[test]
fn a_value_inside_a_string_ends_at_the_closing_quote() {
    for (input, secret) in [
        ("echo \"db_password: LEAKV12\" >> f\n", "LEAKV12"),
        ("curl -H \"X-Api-Key: LEAKV\" -H \"Accept: x\" url\n", "LEAKV"),
        ("print(\"secret = LEAKV\", file=x)\n", "LEAKV"),
        ("s = \"api_key: LEAKV\"; t = 1\n", "LEAKV"),
        ("cmd('--password=LEAKV other')\n", "LEAKV"),
    ] {
        assert_gone(input, secret);
    }
    assert_eq!(clean("s = \"api_key: V1\"; t = 1\n").unwrap(), "s = \"api_key: [REDACTED]\"; t = 1\n");
    assert_eq!(clean("c = \"Password=abc;User Id=bob\"\n").unwrap(), "c = \"Password=[REDACTED];User Id=bob\"\n");
    assert_kept("log(\"token={token}\")\n");
}

#[test]
fn more_yaml_shapes_under_secret_names() {
    for (input, want) in [
        ("password: &p LEAK\n", "password: &p [REDACTED]\n"),
        ("password:\n  LEAK\nname: x\n", "password:\n  [REDACTED]\nname: x\n"),
        ("passwords: [A1, B2]\n", "passwords: [[REDACTED]]\n"),
        ("secrets:\n  a: LEAK1\n  b:\n    c: LEAK2\nname: x\n", "secrets:\n  a: [REDACTED]\n  b:\n    c: [REDACTED]\nname: x\n"),
        ("tokens:\n  - one\n  # a note\n  - two\nname: x\n", "tokens:\n  - [REDACTED]\n  # a note\n  - [REDACTED]\nname: x\n"),
        ("tokens:\n  - id: 1\n    value: LEAK\n", "tokens:\n  - id: 1\n    value: [REDACTED]\n"),
    ] {
        assert_eq!(clean(input).unwrap(), want, "{input:?}");
    }
}

#[test]
fn toml_tables_and_json_objects_under_secret_names() {
    assert_eq!(
        clean("[app]\nname = \"x\"\n[secrets]\ndb = \"LEAK1\"\nkey = LEAK2\n[other]\nport = 1\n").unwrap(),
        "[app]\nname = \"x\"\n[secrets]\ndb = [REDACTED]\nkey = [REDACTED]\n[other]\nport = 1\n"
    );
    assert_eq!(clean("[database.credentials]\nvalue = LEAK\n").unwrap(), "[database.credentials]\nvalue = [REDACTED]\n");
    // Other tables keep their values; only secret-named keys are hidden.
    assert_eq!(
        clean("[auth]\nenabled = true\nsite_url = \"http://localhost:3000\"\njwt_expiry = 3600\n").unwrap(),
        "[auth]\nenabled = true\nsite_url = \"http://localhost:3000\"\njwt_expiry = 3600\n"
    );
    assert_eq!(
        clean("{\n  \"secret\": {\n    \"a\": \"LEAK1\",\n    \"b\": [\"LEAK2\"]\n  },\n  \"name\": \"x\"\n}\n").unwrap(),
        "{\n  \"secret\": {\n    \"a\": [REDACTED],\n    \"b\": [[REDACTED]]\n  },\n  \"name\": \"x\"\n}\n"
    );
}

#[test]
fn every_value_in_a_kubernetes_secret_is_hidden() {
    let input = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  user: YWRt\n  pw: c2Vj\nstringData:\n  url: plain\n---\nkind: ConfigMap\ndata:\n  mode: fast\n";
    let want = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  user: [REDACTED]\n  pw: [REDACTED]\nstringData:\n  url: [REDACTED]\n---\nkind: ConfigMap\ndata:\n  mode: fast\n";
    assert_eq!(clean(input).unwrap(), want);
}

#[test]
fn xml_name_and_value_pairs() {
    for (input, want) in [
        ("<property>\n  <name>db.password</name>\n  <value>LEAK</value>\n</property>\n", "<property>\n  <name>db.password</name>\n  <value>[REDACTED]</value>\n</property>\n"),
        ("<name>fs.s3a.secret.key</name><value>LEAK</value>\n", "<name>fs.s3a.secret.key</name><value>[REDACTED]</value>\n"),
        ("<entry key=\"password\">LEAK</entry>\n", "<entry key=\"password\">[REDACTED]</entry>\n"),
        ("<setting name=\"ApiKey\" serializeAs=\"String\">\n  <value>LEAK</value>\n</setting>\n", "<setting name=\"ApiKey\" serializeAs=[REDACTED]>\n  <value>[REDACTED]</value>\n</setting>\n"),
        ("<add key=\"ApiKey\" value=\"LEAK\" />\n", "<add key=\"ApiKey\" value=[REDACTED] />\n"),
        ("<name>db.user</name><value>bob</value>\n", "<name>db.user</name><value>bob</value>\n"),
    ] {
        assert_eq!(clean(input).unwrap(), want, "{input:?}");
    }
}

#[test]
fn unquoted_values_with_spaces_run_to_the_end_of_the_line() {
    for (input, want) in [
        ("password = correct LEAK horse\n", "password = [REDACTED]\n"),
        ("DB_PASSWORD=a LEAK b\n", "DB_PASSWORD=[REDACTED]\n"),
        ("ENV DB_PASSWORD LEAK value\n", "ENV DB_PASSWORD [REDACTED]\n"),
        ("ENV DB_PASSWORD=LEAK\n", "ENV DB_PASSWORD=[REDACTED]\n"),
        ("Authorization: Digest username=LEAK\n", "Authorization: [REDACTED]\n"),
        ("Authorization: Token LEAK\n", "Authorization: [REDACTED]\n"),
    ] {
        assert_eq!(clean(input).unwrap(), want, "{input:?}");
    }
    for input in ["token = token or default\n", "password = a if b else c\n", "password = get(x)\n"] {
        assert_kept(input);
    }
}

#[test]
fn python_type_hints_are_types_not_values() {
    for input in ["class S:\n    api_key: str | None\n", "class S:\n    secret: dict[str, Any]\n", "class S:\n    token: Optional[str]\n"] {
        assert_kept(input);
    }
}

#[test]
fn more_sensitive_file_names() {
    for p in [
        "env", "env.local", "env.json", "config/prod-env", "dotenv", ".vault-token", "kubeconfig", ".my.cnf", ".s3cfg",
        ".boto", "prod.tfvars.json", "id_rsa.bak", ".npmrc.bak", "cert.p12.bak", "wp-config.php.bak", ".env.swp",
        ".id_rsa.swp", "config.env~", ".netrc.orig", "secrets.yml.old", "my_id_rsa", "deploy_id_ed25519",
    ] {
        assert!(is_sensitive_path(p), "{p}");
    }
    for p in ["env.ts", "src/env.rs", "env.d.ts", "env.example", "id_rsa.pub", ".env.example", "environment.js", "README.md.bak"] {
        assert!(!is_sensitive_path(p), "{p}");
    }
}

// ---- QA round 3: real shapes that must stay readable ----

#[test]
fn real_config_and_code_shapes_are_not_redacted() {
    let fixtures = [
        // argo-helm CRD schema under a secret-named property.
        "auth:\n  properties:\n    passwordSecret:\n      description: PasswordSecret is the secret selector to the repository password\n      properties:\n        key:\n          description: The key of the secret to select from.\n          type: string\n        name:\n          description: Name of the referent.\n          type: string\n      required:\n      - key\n      type: object\n",
        // Chart values.
        "credentials:\n  enabled: true\n  region: us-east-1\nsecret:\n  enabled: false\n  create: true\n",
        // Supabase config.toml.
        "[auth]\nenabled = true\nsite_url = \"http://127.0.0.1:3000\"\njwt_expiry = 3600\nenable_signup = true\n",
        // rubygems en.yml.
        "en:\n  password_reset: Reset your password by clicking the link\n  credentials_required: Credentials required\n  token_expired: Your token has expired\n",
        // Helm template under imagePullSecrets.
        "spec:\n  imagePullSecrets:\n    {{- toYaml . | nindent 8 }}\n  password: {{ .Values.password | quote }}\n",
        // Compose secrets.
        "secrets:\n  db_password:\n    file: ./db_password.txt\n  api_key:\n    external: true\n",
        // OpenAPI password field.
        "components:\n  schemas:\n    Login:\n      properties:\n        password:\n          type: string\n          format: password\n          description: The user's password\n          minLength: 8\n",
        // JSON Schema under a quoted password key.
        "{\n  \"password\": {\n    \"type\": \"string\",\n    \"description\": \"The user's password\"\n  },\n  \"label\": \"x\"\n}\n",
        // GitHub Actions job named bearer.
        "jobs:\n  bearer:\n    runs-on: ubuntu-latest\n    needs: build\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n",
        // Rust lifetimes.
        "fn f<'a>(password: String, n: &'a str) -> &'a str {\n    n\n}\n",
        // Prose inside a string.
        "raise ValueError(\"Invalid token: expected 3 parts\")\n",
        // Comment after a code value; a command after an env assignment.
        "token = None  # set later\n",
        // JSX form field with a secret-ish name.
        "<FormField\n  control={form.control}\n  name=\"REFRESH_TOKEN_ROTATION_ENABLED\"\n  render={({ field }) => (\n    <FormItemLayout\n",
        // A list of error codes under auth, and a zod chain.
        "const C = {\n  auth: [\n    { code: 'session_not_found', description: 'User session not found' },\n  ],\n}\nconst schema = z.object({\n  password: z\n    .string()\n})\n",
        // i18n labels under secret-named keys.
        "en:\n  forgot_password: Forgot password?\n  new_api_key: New API key\n  count: \"%{count} tokens\"\n",
        // Chart values naming Secrets and files, and a Secret's metadata.
        "tlsSecret:\n  enabled: false\n  certItem: tls.crt\n  keyItem: tls.key\nglobal:\n  imagePullSecrets:\n  - pullSecret1\n",
        "repo-credentials:\n  apiVersion: v1\n  metadata:\n    labels:\n      argocd.argoproj.io/secret-type: repository\n",
        // TypeScript and JSX.
        "token = captchaResponse?.response ?? null\n",
        "<AuthContext.Provider value={value}>{children}</AuthContext.Provider>\n<Token>{t}</Token>\n",
        "<TableHead key=\"access-key-id\">Access key ID</TableHead>\n",
        "const keys: ApiKey[] = [\n  { name: 'publishable', type: 'publishable' },\n]\n",
        "{\n  'v1-list-all-secrets': {\n    content: {\n      'application/json': components['schemas']['SecretResponse'][]\n    }\n  }\n}\n",
        // SecretKeySelectors: `key` names a field of a Kubernetes Secret.
        "authorization:\n  credentials:\n    name: my-token-secret\n    key: token\ns3:\n  accessKeySecret:\n    name: minio\n    key: accesskey\n",
        // Round 5: byte literals, placeholders, block scalars that name a field, a plain env var.
        "Token::U8(b'x'),\nlet buf = [b'\\0'; 32 * 1024]; // token\n",
        "q = \"user=%s password=%s\"\nf\"host=x password={pw}\"\nc = \"Password={0};Server=x\"\nsql = \"WHERE password = ?\"\n",
        "token_endpoint_auth_methods: |\n  client_secret_basic\nsecret_key_name: |\n  my-key\n",
        "env:\n  - name: HOST\n    value: db\n  - name: API_KEY\n    valueFrom:\n      secretKeyRef:\n        name: x\n",
        "variable \"region\" {\n  default = \"us-east-1\"\n}\n",
        // Restored: a section named auth.
        "auth:\n  user: bob\n  method: basic\n",
    ];
    for f in fixtures {
        let out = clean(f).unwrap();
        assert!(!out.contains(MARK), "over-redacted:\n{f}\n---\n{out}");
    }
    assert_eq!(clean("PASSWORD=hunter2x ./run.sh\n").unwrap(), "PASSWORD=[REDACTED] ./run.sh\n");
}

#[test]
fn secrets_inside_real_shapes_are_still_hidden() {
    for (input, secret) in [
        ("secrets:\n  db_password:\n    value: LEAKA1\n", "LEAKA1"),
        ("credentials:\n  enabled: true\n  access_key_id: LEAKA2\n", "LEAKA2"),
        ("[auth]\nenabled = true\njwt_secret = \"LEAKA3\"\n", "LEAKA3"),
        ("{\n  \"secrets\": {\n    \"type\": \"string\",\n    \"db\": \"LEAKA4\"\n  }\n}\n", "LEAKA4"),
        ("en:\n  db_password: LEAKA5 words\n", "LEAKA5"),
        ("echo \"db_password: LEAKA6\" >> f\n", "LEAKA6"),
        ("class A {\n  authorization: string = hunterAB15\n}\n", "hunterAB15"),
    ] {
        assert_gone(input, secret);
    }
}

#[test]
fn ssh_key_names_in_code_files_are_not_sensitive() {
    for p in ["id_rsa.py", "src/my_id_rsa.rs", "id_rsa_parser.rs", "id_ed25519.go"] {
        assert!(!is_sensitive_path(p), "{p}");
    }
    for p in ["id_rsa", "my_id_rsa", "deploy_id_ed25519", "id_rsa.bak"] {
        assert!(is_sensitive_path(p), "{p}");
    }
}

#[test]
fn round_four_shapes() {
    for (input, secret) in [
        ("password = b'plainleak'\n", "plainleak"),
        ("password = RB'plainleak'\n", "plainleak"),
        ("conn = \"dbname=t user=u password=plainleak host=x\"\n", "plainleak"),
        ("-H \"X-Api-Key: ab$plainleak\"\n", "plainleak"),
        ("secrets:\n  - name: x\n    value: plainleak\n", "plainleak"),
        ("secret_value: |\n  plainleak\n", "plainleak"),
    ] {
        assert_gone(input, secret);
    }
    // Lifetimes and English stay; a variable reference is not a value; k8s comments stay.
    for input in [
        "fn f<'a>(x: &'a str) -> &'a str { x }\n",
        "// don't log it's token\n",
        "-H \"Authorization: Bearer $TOKEN\"\n",
        "kind: Secret\ndata:\n  # the database user\n",
        "{\"password\": [\n  {\"href\": \"http://a\", \"comment\": \"x\"}\n]}\n",
    ] {
        assert_kept(input);
    }
    assert_eq!(clean("conn = \"dbname=t password=pw1 host=db\"\n").unwrap(), "conn = \"dbname=t password=[REDACTED] host=db\"\n");
}
