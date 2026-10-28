//! mc-trust: trust Mintsifry certificates only for the domains you choose.

mod linux;
mod macos;
mod probe;
mod store;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;

use mc_trust_core::{
    audit, build_grant, dns_name_matches, host_allowed, is_tld, normalize_domain, time, Cert, Kind, MintsifryRoot,
    PinPolicy, DEFAULT_ZONES,
};

use store::{Found, TrustStore};
use util::{confirm, Res};

/// Must open after install: on .ru, served with a Mintsifry chain.
const POSITIVE_HOST: &str = "online.sberbank.ru";
/// Must be rejected after install: outside the zones, also on a Mintsifry chain.
const NEGATIVE_HOST: &str = "sberbank.com";
/// Exit code when a check could not be completed: no network, no Mintsifry chain, no proof.
const INCOMPLETE: u8 = 3;

const HELP: &str = "\
mc-trust — доверять сертификатам Минцифры только для выбранных доменов

Использование: mc-trust <команда> [флаги]

Команды:
  install     Поставить grant: свой CA + копию корня Минцифры с ограничением имён,
              удалить оригинальный корень, проверить результат
  status      Что установлено сейчас
  check ХОСТ… Проверить сайты: выпущены ли Минцифры и принимает ли их система
  uninstall   Удалить grant (оригинальный корень не возвращается)

Флаги install:
  -d, --domain ДОМЕН   Добавить домен (можно несколько раз или через запятую).
                       sberbank.com — домен и поддомены; .example.com — только поддомены
  --no-default-zones   Без зон по умолчанию (.ru, .su, .xn--p1ai = .рф)
  --root ФАЙЛ          Корень Минцифры из файла вместо встроенного
  --allow-unpinned     Принять корень с ключом, отличным от зашитого
  --no-check           Не проверять сайты после установки
  -y, --yes            Не спрашивать подтверждение
  --dry-run            Показать план и ничего не менять

Флаги uninstall: -y, --yes; --dry-run

Коды выхода: 0 — успех; 1 — ошибка или ограничение не работает;
2 — не указана команда; 3 — проверка неполная (хосты не удалось проверить)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Ошибка: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Res<ExitCode> {
    let Some(cmd) = args.first() else {
        print!("{HELP}");
        return Ok(ExitCode::from(2));
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "install" => install(InstallOpts::parse(rest)?),
        "status" => {
            no_args(rest)?;
            status()
        }
        "check" => check(rest),
        "uninstall" => uninstall(rest),
        "help" | "-h" | "--help" => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        "version" | "-V" | "--version" => {
            println!("mc-trust {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("неизвестная команда «{other}»; см. mc-trust help").into()),
    }
}

fn no_args(rest: &[String]) -> Res<()> {
    match rest.first() {
        Some(a) => Err(format!("лишний аргумент «{a}»").into()),
        None => Ok(()),
    }
}

// ------------------------------------------------------------------ install

struct InstallOpts {
    extra: Vec<String>,
    default_zones: bool,
    root: Option<PathBuf>,
    allow_unpinned: bool,
    check: bool,
    yes: bool,
    dry_run: bool,
}

impl InstallOpts {
    fn parse(rest: &[String]) -> Res<InstallOpts> {
        let mut o = InstallOpts {
            extra: Vec::new(),
            default_zones: true,
            root: None,
            allow_unpinned: false,
            check: true,
            yes: false,
            dry_run: false,
        };
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
                _ => (arg.as_str(), None),
            };
            if inline.is_some() && !matches!(flag, "-d" | "--domain" | "--root") {
                return Err(format!("флаг «{flag}» не принимает значение").into());
            }
            let mut value = |name: &str| -> Res<String> {
                inline
                    .clone()
                    .or_else(|| it.next().cloned())
                    .ok_or_else(|| format!("{name} требует значение").into())
            };
            match flag {
                "-d" | "--domain" => {
                    for part in value("--domain")?.split(',').filter(|p| !p.trim().is_empty()) {
                        o.extra.push(normalize_domain(part)?);
                    }
                }
                "--root" => o.root = Some(PathBuf::from(value("--root")?)),
                "--no-default-zones" => o.default_zones = false,
                "--allow-unpinned" => o.allow_unpinned = true,
                "--no-check" => o.check = false,
                "-y" | "--yes" => o.yes = true,
                "--dry-run" => o.dry_run = true,
                other => return Err(format!("неизвестный флаг «{other}»").into()),
            }
        }
        Ok(o)
    }

    fn domains(&self) -> Res<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        let zones = DEFAULT_ZONES.iter().map(|z| z.to_string()).filter(|_| self.default_zones);
        for d in zones.chain(self.extra.iter().cloned()) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
        if out.is_empty() {
            return Err("список доменов пуст: уберите --no-default-zones или добавьте --domain".into());
        }
        Ok(out)
    }

    fn load_root(&self) -> Res<MintsifryRoot> {
        let Some(path) = &self.root else {
            return Ok(MintsifryRoot::embedded()?);
        };
        let policy = if self.allow_unpinned { PinPolicy::AllowUnpinned } else { PinPolicy::Require };
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(MintsifryRoot::from_bytes(&bytes, policy)?)
    }
}

fn describe(f: &Found) -> String {
    let what = match &f.kind {
        Kind::OriginalRoot => "оригинальный корень Минцифры".to_string(),
        Kind::MintsifrySub => format!(
            "промежуточный сертификат Минцифры ({})",
            f.cert.subject_cn().unwrap_or_default()
        ),
        Kind::GrantCa { id } => format!("CA mc-trust {id}"),
        Kind::GrantCopy { id } => format!("копия корня от grant'а {id}"),
        Kind::Other => "сертификат".to_string(),
    };
    format!("{what} — {}", f.location.label())
}

fn install(o: InstallOpts) -> Res<ExitCode> {
    let root = o.load_root()?;
    let domains = o.domains()?;
    println!(
        "Корень Минцифры: SPKI SHA-256 {}{}",
        root.spki_sha256_hex(),
        if root.is_pinned() { " (совпадает с зашитым)" } else { " (НЕ совпадает с зашитым)" }
    );
    println!("Разрешённые домены: {}", domains.join(", "));
    let wide: Vec<&str> = domains
        .iter()
        .map(|d| d.as_str())
        .filter(|d| is_tld(d) && !DEFAULT_ZONES.contains(d))
        .collect();
    if !wide.is_empty() {
        println!(
            "Внимание: {} — зона верхнего уровня, Минцифры сможет подтверждать любые сайты в ней.",
            wide.join(", ")
        );
        if !o.yes && !o.dry_run && !confirm("Всё равно продолжить?")? {
            println!("Отменено, ничего не изменено.");
            return Ok(ExitCode::from(1));
        }
    }

    let kc = store::detect()?;
    let found = kc.scan()?;
    let mintsifry: Vec<&Found> = found
        .iter()
        .filter(|f| matches!(f.kind, Kind::OriginalRoot | Kind::MintsifrySub))
        .collect();
    let old: Vec<&Found> = found
        .iter()
        .filter(|f| matches!(f.kind, Kind::GrantCa { .. } | Kind::GrantCopy { .. }))
        .collect();

    println!("\nПлан:");
    println!("  • выпустить новый grant и добавить его в {}", kc.target());
    for f in &old {
        println!("  • удалить {}", describe(f));
    }
    for f in &mintsifry {
        println!("  • удалить {}", describe(f));
    }
    if o.check {
        println!("  • проверить: {POSITIVE_HOST} должен открываться, {NEGATIVE_HOST} — нет");
    }
    for f in old.iter().chain(mintsifry.iter()) {
        kc.removable(f)?;
    }
    if o.dry_run {
        println!("\n--dry-run: ничего не изменено.");
        return Ok(ExitCode::SUCCESS);
    }
    if !mintsifry.is_empty() && !o.yes {
        println!("\nСертификаты Минцифры в хранилище обходят ограничения, поэтому их нужно удалить.");
        if !confirm("Продолжить?")? {
            println!("Отменено, ничего не изменено.");
            return Ok(ExitCode::from(1));
        }
    }

    let grant = build_grant(&root, &domains, time::now_unix()?)?;
    println!("\nGrant {} выпущен, ключ CA уничтожен.", grant.id);
    kc.install_grant(&grant)?;
    println!("Grant добавлен в {}.", kc.target());
    for f in old.iter().chain(mintsifry.iter()) {
        kc.remove(f)?;
        println!("Удалён: {}", describe(f));
    }

    if !o.check {
        println!("\nГотово. Проверка пропущена: mc-trust check {POSITIVE_HOST} {NEGATIVE_HOST}");
        return Ok(ExitCode::SUCCESS);
    }
    println!("\nПроверка:");
    let positive = report(kc.as_ref(), &root, POSITIVE_HOST, &grant.domains);
    let negative = if host_allowed(NEGATIVE_HOST, &grant.domains) {
        println!("  {NEGATIVE_HOST}: в вашем списке доменов, отрицательная проверка невозможна");
        Verdict::Skipped
    } else {
        report(kc.as_ref(), &root, NEGATIVE_HOST, &grant.domains)
    };

    if negative == Verdict::Mismatch {
        eprintln!(
            "\n{} принимает {NEGATIVE_HOST}, хотя он вне списка: ограничение имён не соблюдается. \
             Откатываю grant — сайты на сертификатах Минцифры открываться не будут.",
            kc.verifier()
        );
        for f in kc.scan()? {
            let ours = matches!(&f.kind, Kind::GrantCa { id } | Kind::GrantCopy { id } if *id == grant.id);
            if ours {
                kc.remove(&f)?;
            }
        }
        return Ok(ExitCode::from(1));
    }
    match (positive, negative) {
        (Verdict::Match, Verdict::Match) => println!("\nГотово: ограничение работает."),
        (Verdict::Mismatch, _) => {
            eprintln!("\nGrant установлен, но {POSITIVE_HOST} не принимается. Попробуйте: mc-trust check {POSITIVE_HOST}");
            return Ok(ExitCode::from(1));
        }
        _ => {
            println!(
                "\nGrant установлен, но проверка неполная. Повторите позже: mc-trust check {POSITIVE_HOST} {NEGATIVE_HOST}"
            );
            return Ok(ExitCode::from(INCOMPLETE));
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ check

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Match,
    Mismatch,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Issuer {
    /// A certificate in the chain is signed by the pinned root.
    Mintsifry,
    /// The chain names the Mintsifry root but the signature does not verify.
    BadSignature,
    /// The chain stops at a Mintsifry intermediate that the server did not send.
    MintsifryLikely,
    Other,
}

fn issuer_of(root: &MintsifryRoot, chain: &[Cert]) -> Issuer {
    let mut result = Issuer::Other;
    for cert in chain {
        match root.signed(cert) {
            Some(true) => return Issuer::Mintsifry,
            Some(false) => result = Issuer::BadSignature,
            None => {}
        }
    }
    let last_issuer = chain.last().and_then(|c| c.issuer_cn()).unwrap_or_default();
    if result == Issuer::Other && last_issuer.starts_with("Russian Trusted Sub CA") {
        return Issuer::MintsifryLikely;
    }
    result
}

/// Accepting what should be rejected, or rejecting what should be accepted, is a mismatch.
/// A rejection that should happen counts only with evidence that the chain is otherwise valid.
fn judge(accepted: bool, expected: bool, evidence: bool) -> Verdict {
    match (accepted, expected) {
        (a, e) if a != e => Verdict::Mismatch,
        (false, false) if !evidence => Verdict::Skipped,
        _ => Verdict::Match,
    }
}

/// A rejection proves the name constraints work only if the chain would be valid without
/// them: it reaches the pinned root, every link is in date, and the leaf covers `host`.
fn rejection_is_evidence(root: &MintsifryRoot, chain: &[Cert], host: &str, now: i64) -> bool {
    let Some(leaf) = chain.first() else { return false };
    let covers = leaf
        .san_dns()
        .is_ok_and(|names| names.iter().any(|n| dns_name_matches(n, host)));
    if !covers || now > root.not_after() {
        return false;
    }
    let mut cur = leaf;
    for _ in 0..chain.len() {
        if cur.not_before > now || cur.not_after < now {
            return false;
        }
        if root.signed(cur) == Some(true) {
            return true;
        }
        match chain
            .iter()
            .find(|c| c.subject_raw == cur.issuer_raw && cur.verify_signed_by(c).is_ok())
        {
            Some(next) => cur = next,
            None => return false,
        }
    }
    false
}

/// Prints one host's result and compares it with what the domain list implies.
fn report(kc: &dyn TrustStore, root: &MintsifryRoot, target: &str, permitted: &[String]) -> Verdict {
    let outcome = (|| -> Res<(String, Issuer, bool, bool)> {
        let (host, port) = probe::parse_target(target)?;
        let chain = probe::fetch_chain(&host, port)?;
        let certs = chain.iter().map(|d| Cert::from_der(d)).collect::<Result<Vec<_>, _>>()?;
        let issuer = issuer_of(root, &certs);
        let accepted = kc.verify(&host, &chain)?;
        let evidence = rejection_is_evidence(root, &certs, &host, time::now_unix()?);
        Ok((host, issuer, accepted, evidence))
    })();
    let (host, issuer, accepted, evidence) = match outcome {
        Ok(v) => v,
        Err(e) => {
            println!("  {target}: пропущено ({e})");
            return Verdict::Skipped;
        }
    };
    let accepted_word = if accepted { "принимает" } else { "отклоняет" };
    let verifier = kc.verifier();
    match issuer {
        Issuer::Mintsifry | Issuer::MintsifryLikely => {
            let expected = host_allowed(&host, permitted);
            let verdict = judge(accepted, expected, evidence);
            let mark = match verdict {
                Verdict::Match => "✓",
                Verdict::Mismatch => "✗",
                Verdict::Skipped => {
                    "? отказ не доказывает работу ограничения (цепочка не проверена до корня, просрочена или не покрывает хост)"
                }
            };
            println!(
                "  {host}: цепочка Минцифры{}, {verifier} {accepted_word}, ожидалось {} — {mark}",
                if issuer == Issuer::MintsifryLikely { " (Sub CA не прислан)" } else { "" },
                if expected { "принять" } else { "отклонить" },
            );
            verdict
        }
        Issuer::BadSignature => {
            println!(
                "  {host}: цепочка ссылается на корень Минцифры, но подпись не сходится с зашитым ключом; \
                 {verifier} {accepted_word} — ✗"
            );
            Verdict::Mismatch
        }
        Issuer::Other => {
            println!("  {host}: цепочка не от Минцифры, {verifier} {accepted_word} — к mc-trust не относится");
            Verdict::Skipped
        }
    }
}

fn installed_domains(found: &[Found]) -> Vec<String> {
    let mut out = Vec::new();
    for f in found {
        if let Kind::GrantCa { .. } = f.kind {
            for d in f.cert.permitted_dns().ok().flatten().unwrap_or_default() {
                if !out.contains(&d) {
                    out.push(d);
                }
            }
        }
    }
    out
}

fn check(targets: &[String]) -> Res<ExitCode> {
    if targets.is_empty() {
        return Err("укажите хотя бы один хост: mc-trust check online.sberbank.ru".into());
    }
    let kc = store::detect()?;
    let root = MintsifryRoot::embedded()?;
    let permitted = installed_domains(&kc.scan()?);
    if permitted.is_empty() {
        println!("Grant не установлен: для сайтов Минцифры ожидается отказ.");
    }
    let (mut mismatch, mut incomplete) = (false, false);
    for t in targets {
        match report(kc.as_ref(), &root, t, &permitted) {
            Verdict::Mismatch => mismatch = true,
            Verdict::Skipped => incomplete = true,
            Verdict::Match => {}
        }
    }
    Ok(if mismatch {
        ExitCode::from(1)
    } else if incomplete {
        ExitCode::from(INCOMPLETE)
    } else {
        ExitCode::SUCCESS
    })
}

// ------------------------------------------------------------------ status

fn status() -> Res<ExitCode> {
    let kc = store::detect()?;
    let found = kc.scan()?;
    let root = MintsifryRoot::embedded()?;
    let mut healthy = true;

    let cas: Vec<&Found> = found.iter().filter(|f| matches!(f.kind, Kind::GrantCa { .. })).collect();
    if cas.is_empty() {
        println!("Grant не установлен.");
        healthy = false;
    }
    for ca in &cas {
        let Kind::GrantCa { id } = &ca.kind else { continue };
        let copy = found
            .iter()
            .find(|f| matches!(&f.kind, Kind::GrantCopy { id: cid } if cid == id));
        let domains = ca.cert.permitted_dns().ok().flatten().unwrap_or_default();
        println!("Grant {id}");
        println!("  CA: {}", ca.location.label());
        match copy {
            Some(c) => {
                println!("  копия корня: {}", c.location.label());
                for problem in audit(&root, &ca.cert, &c.cert) {
                    println!("  ! {problem}");
                    healthy = false;
                }
            }
            None => {
                println!("  копия корня: НЕ НАЙДЕНА — переустановите: mc-trust install");
                healthy = false;
            }
        }
        println!("  домены: {}", domains.join(", "));
        println!("  действует до: {}", time::format_human(ca.cert.not_after));
        if ca.cert.not_after < time::now_unix()? {
            println!("  СРОК ИСТЁК");
            healthy = false;
        }
    }
    if cas.len() > 1 {
        println!("Установлено несколько grant'ов; mc-trust install оставит один.");
        healthy = false;
    }
    for orphan in found.iter().filter(|f| {
        matches!(&f.kind, Kind::GrantCopy { id } if !cas.iter().any(|c| matches!(&c.kind, Kind::GrantCa { id: cid } if cid == id)))
    }) {
        println!("Копия корня без своего CA ({}): mc-trust install уберёт её.", orphan.location.label());
        healthy = false;
    }
    for f in found.iter().filter(|f| matches!(f.kind, Kind::OriginalRoot | Kind::MintsifrySub)) {
        println!("! {}: с ним ограничения не работают. Запустите mc-trust install.", describe(f));
        healthy = false;
    }
    Ok(if healthy { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

// ------------------------------------------------------------------ uninstall

fn uninstall(rest: &[String]) -> Res<ExitCode> {
    let mut yes = false;
    let mut dry_run = false;
    for a in rest {
        match a.as_str() {
            "-y" | "--yes" => yes = true,
            "--dry-run" => dry_run = true,
            other => return Err(format!("неизвестный флаг «{other}»").into()),
        }
    }
    let kc = store::detect()?;
    let ours: Vec<Found> = kc
        .scan()?
        .into_iter()
        .filter(|f| matches!(f.kind, Kind::GrantCa { .. } | Kind::GrantCopy { .. }))
        .collect();
    if ours.is_empty() {
        println!("Нечего удалять: grant не установлен.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("Будет удалено:");
    for f in &ours {
        println!("  • {}", describe(f));
        kc.removable(f)?;
    }
    if dry_run {
        println!("--dry-run: ничего не изменено.");
        return Ok(ExitCode::SUCCESS);
    }
    if !yes && !confirm("Удалить?")? {
        println!("Отменено.");
        return Ok(ExitCode::from(1));
    }
    for f in &ours {
        kc.remove(f)?;
        println!("Удалён: {}", describe(f));
    }
    println!(
        "Готово. Оригинальный корень Минцифры не возвращается: сайты на его сертификатах перестанут открываться."
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn install_flags() {
        let o = InstallOpts::parse(&args(&["-d", "sberbank.com,vtb.com", "--domain=Example.org", "--yes"])).unwrap();
        assert_eq!(
            o.domains().unwrap(),
            [".ru", ".su", ".xn--p1ai", "sberbank.com", "vtb.com", "example.org"]
        );
        assert!(o.yes);
        let o = InstallOpts::parse(&args(&["--no-default-zones"])).unwrap();
        assert!(o.domains().is_err());
        assert!(InstallOpts::parse(&args(&["--bogus"])).is_err());
        assert!(InstallOpts::parse(&args(&["--domain"])).is_err());
    }

    #[test]
    fn flags_without_a_value_reject_one() {
        assert!(InstallOpts::parse(&args(&["--allow-unpinned=false"])).is_err());
        assert!(InstallOpts::parse(&args(&["--yes=no"])).is_err());
        assert!(InstallOpts::parse(&args(&["--no-check=false"])).is_err());
        assert!(InstallOpts::parse(&args(&["--root=/tmp/root.pem"])).is_ok());
    }

    #[test]
    fn a_rejection_counts_only_with_evidence() {
        assert_eq!(judge(false, false, true), Verdict::Match);
        assert_eq!(judge(false, false, false), Verdict::Skipped);
        assert_eq!(judge(true, true, false), Verdict::Match);
        assert_eq!(judge(true, false, true), Verdict::Mismatch);
        assert_eq!(judge(false, true, true), Verdict::Mismatch);
    }

    #[test]
    fn sub_ca_alone_is_mintsifry_but_not_evidence() {
        let root = MintsifryRoot::embedded().unwrap();
        let pem = include_str!("../../core/tests/data/russian_trusted_sub_ca.pem");
        let der = mc_trust_core::pem::certificate_der(pem.as_bytes()).unwrap();
        let sub = Cert::from_der(&der).unwrap();
        assert_eq!(issuer_of(&root, std::slice::from_ref(&sub)), Issuer::Mintsifry);
        assert_eq!(issuer_of(&root, &[]), Issuer::Other);
        // A Sub CA has no host names, so rejecting it says nothing about name constraints.
        let now = time::now_unix().unwrap();
        assert!(!rejection_is_evidence(&root, std::slice::from_ref(&sub), "online.sberbank.ru", now));
        assert!(!rejection_is_evidence(&root, &[], "online.sberbank.ru", now));
    }
}
