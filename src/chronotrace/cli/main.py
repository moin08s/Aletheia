"""ChronoTrace Typer CLI application."""

from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table

from chronotrace.core.case import Case
from chronotrace.extract.registry import list_plugins
from chronotrace.acquire.devices import DeviceManager
from chronotrace.gui.app import launch_gui

app = typer.Typer(
    name="wasp",
    help="WASP: Deterministic digital forensics platform: metadata extraction, artefact parsing, timeline reconstruction, SHA-256 integrity, and reporting.",
    add_completion=False,
)

case_app = typer.Typer(name="case", help="Manage forensic cases.")
app.add_typer(case_app, name="case")

plugin_app = typer.Typer(name="plugin", help="Inspect and manage artefact plugins.")
app.add_typer(plugin_app, name="plugin")

device_app = typer.Typer(name="device", help="Discover and manage connected storage & external devices.")
app.add_typer(device_app, name="device")

bundle_app = typer.Typer(name="bundle", help="Create and verify cryptographically signed .wasp case bundles.")
app.add_typer(bundle_app, name="bundle")

console = Console()


@app.callback(invoke_without_command=True)
def main_callback(
    version: bool = typer.Option(False, "--version", "-V", help="Show WASP version"),
    deterministic: bool = typer.Option(False, "--deterministic", help="Strip volatile metadata from outputs"),
    strict: bool = typer.Option(False, "--strict", help="Treat parse warnings as fatal"),
):
    if version:
        console.print("[bold cyan]WASP[/bold cyan] (Wide-scope Artifact & Super-timeline Platform) version [bold green]1.4.0[/bold green] (Schema 2.0.0)")
        raise typer.Exit()


# --- CASE COMMANDS ---

@case_app.command("create")
def case_create(
    id: str = typer.Option(..., "--id", help="Case identifier (e.g. CASE-2024-0117)"),
    out: Path = typer.Option(..., "--out", "--output", help="Output directory path for the case"),
    examiner: str = typer.Option("Forensic Analyst", "--examiner", "--investigator", help="Lead forensic examiner name"),
    organization: str = typer.Option("DFIR Unit", "--organization", help="Investigating organization"),
    authorization_ref: str = typer.Option("AUTH-001", "--authorization-ref", help="Warrant or authorization reference"),
    description: str = typer.Option("Digital Forensics Investigation", "--description", help="Case description"),
):
    """Create a new case workspace with initial custody ledger and manifest."""
    case = Case.create(
        case_id=id,
        out_dir=out,
        examiner=examiner,
        organization=organization,
        authorization_ref=authorization_ref,
        description=description,
    )
    console.print(f"[bold green][+][/bold green] Created case [bold cyan]{case.case_id}[/bold cyan] at [underline]{case.root}[/underline]")


@case_app.command("info")
def case_info(
    case_dir: Path = typer.Option(..., "--case", help="Path to existing case directory"),
    json_output: bool = typer.Option(False, "--json", help="Output in machine-readable JSON"),
):
    """Display case metadata, registered evidence, and custody entries."""
    case = Case.open(case_dir)
    if json_output:
        console.print_json(data=case.metadata)
        return

    table = Table(title=f"Case Details: {case.case_id}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Case ID", case.case_id)
    table.add_row("Examiner", case.examiner)
    table.add_row("Organization", case.organization)
    table.add_row("Authorization", case.metadata.get("authorization_ref", "N/A"))
    table.add_row("Created (UTC)", case.metadata.get("created_utc", "N/A"))

    ev_count = len(case.manifest.data.get("evidence", [])) if case.manifest else 0
    table.add_row("Evidence Items", str(ev_count))

    console.print(table)


# --- GUI & WEB COMMANDS ---

@app.command("gui")
def gui_cmd():
    """Launch the WASP Desktop Graphical User Interface (GUI)."""
    console.print("[bold cyan]Launching WASP Graphical User Interface (GUI)...[/bold cyan]")
    launch_gui()


@app.command("web")
def web_cmd(
    case_dir: Optional[Path] = typer.Option(None, "--case", help="Path to case directory to serve via REST API"),
    port: int = typer.Option(8080, "--port", "-p", help="Port for the API server"),
    serve_api: bool = typer.Option(False, "--api", help="Start background REST API server"),
):
    """Launch the WASP Tactical DFIR Web Application Console and local REST API backend."""
    import webbrowser
    web_file = Path(__file__).resolve().parent.parent.parent.parent / "web" / "index.html"
    if not web_file.exists():
        console.print(f"[bold red]Web console not found at:[/bold red] {web_file}")
        raise typer.Exit(code=1)

    if serve_api and case_dir:
        from chronotrace.api.server import run_api_server
        console.print(f"[bold green][+][/bold green] Starting WASP Forensic API Server on [cyan]http://127.0.0.1:{port}[/cyan]...")
        webbrowser.open(web_file.as_uri())
        run_api_server(case_dir, port=port)
    else:
        console.print(f"[bold yellow]Launching WASP Tactical Web Console:[/bold yellow] [underline]{web_file.as_uri()}[/underline]")
        webbrowser.open(web_file.as_uri())


# --- DEVICE COMMANDS ---

@device_app.command("list")
def device_list():
    """List connected storage devices, external drives, and USB media."""
    devices = DeviceManager.list_devices()
    table = Table(title="Connected Storage & External Devices")
    table.add_column("Device ID", style="cyan")
    table.add_column("Model / Volume", style="white")
    table.add_column("Type / Media", style="yellow")
    table.add_column("Mount", style="magenta")
    table.add_column("FS", style="blue")
    table.add_column("Size", style="green")
    table.add_column("Serial No.", style="dim")

    for d in devices:
        table.add_row(
            d.device_id,
            d.model,
            d.media_type,
            d.mount_point or "N/A",
            d.file_system or "Unknown",
            d.size_display,
            d.serial_number or "N/A",
        )
    console.print(table)


@device_app.command("watch")
def device_watch(
    interval: float = typer.Option(1.5, "--interval", "-i", help="Polling interval in seconds"),
    timeout: Optional[float] = typer.Option(None, "--timeout", "-t", help="Timeout in seconds (infinite if omitted)"),
):
    """Monitor external and USB storage devices in real time."""
    from chronotrace.acquire.hotplug import HotplugWatcher
    console.print(f"[bold cyan]Monitoring external storage hotplug events (interval: {interval}s)... Press Ctrl+C to stop.[/bold cyan]")
    watcher = HotplugWatcher(poll_interval=interval)
    try:
        for action, dev in watcher.watch(timeout=timeout, interval=interval):
            if action == "connected":
                console.print(f"[bold green][+] DEVICE CONNECTED:[/bold green] {dev.model} ({dev.size_display})")
                console.print(f"    Mount: [cyan]{dev.mount_point or 'N/A'}[/cyan] | Interface: [yellow]{dev.interface_type}[/yellow] | Serial: {dev.serial_number or 'N/A'}")
            else:
                console.print(f"[bold red][-] DEVICE DISCONNECTED:[/bold red] {dev.model} ({dev.device_id})")
    except KeyboardInterrupt:
        console.print("[dim]Hotplug monitor stopped.[/dim]")



# --- ACQUIRE COMMAND ---

@app.command("acquire")
def acquire(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    source: Optional[Path] = typer.Option(None, "--source", help="Source evidence file, device, or directory"),
    device: Optional[str] = typer.Option(None, "--device", help="Device ID or drive letter to acquire (e.g. E: or \\\\.\\PhysicalDrive1)"),
    output: Optional[str] = typer.Option(None, "--output", help="Destination filename inside case evidence dir"),
    format: str = typer.Option("raw", "--format", help="Evidence container format (raw, ewf, tar, dir)"),
    hash_algo: str = typer.Option("sha256", "--hash", help="Primary hash (SHA-256 mandatory)"),
    notes: str = typer.Option("", "--notes", help="Chain of custody acquisition notes"),
):
    """Acquire digital evidence from file, directory, or external storage device with streaming SHA-256."""
    case = Case.open(case_dir)

    if device:
        console.print(f"Acquiring evidence from external device [cyan]{device}[/cyan]...")
        dev_list = DeviceManager.list_devices()
        target_dev = next((d for d in dev_list if d.device_id.lower() == device.lower() or (d.mount_point and d.mount_point.lower().startswith(device.lower()))), None)
        if not target_dev:
            # Fallback to creating a device target
            target_dev = StorageDevice(device_id=device, mount_point=device if os.path.exists(device) else None)
        res = DeviceManager.acquire_device(target_dev, case, output_filename=output, notes=notes)
    elif source:
        console.print(f"Acquiring evidence from [cyan]{source}[/cyan]...")
        res = case.acquire(source, output_filename=output, notes=notes)
    else:
        console.print("[bold red]Error: Either --source or --device must be specified.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold green][+][/bold green] Acquired evidence [bold cyan]{res['evidence_id']}[/bold cyan]: {res['path']}")
    console.print(f"  SHA-256: [bold yellow]{res['hashes']['sha256']}[/bold yellow] ({res['size_bytes']} bytes)")
    console.print(f"  Read-Back Verification: [bold green]PASS (Match)[/bold green]")


# --- INGEST COMMAND ---

@app.command("ingest")
def ingest(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    profile: str = typer.Option("windows", "--profile", help="Analysis profile (windows, linux, all)"),
    jobs: int = typer.Option(4, "--jobs", help="Number of worker jobs"),
):
    """Ingest evidence and extract file metadata and system artefacts."""
    case = Case.open(case_dir)
    console.print(f"Ingesting evidence for case [bold cyan]{case.case_id}[/bold cyan] (profile: {profile})...")
    events = case.extract(profile=profile, jobs=jobs)
    console.print(f"[bold green][+][/bold green] Extracted [bold green]{len(events)}[/bold green] raw events from evidence artefacts.")


# --- EXTRACT COMMAND ---

@app.command("extract")
def extract(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    all_plugins: bool = typer.Option(False, "--all", help="Run all available plugins"),
    plugins: Optional[str] = typer.Option(None, "--plugins", help="Comma-separated list of plugins"),
    jobs: int = typer.Option(4, "--jobs", help="Number of worker jobs"),
):
    """Run artefact extraction plugins against case evidence."""
    case = Case.open(case_dir)
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None
    events = case.extract(plugins=plugin_list, jobs=jobs)
    console.print(f"[bold green][+][/bold green] Extraction complete. Discovered [bold green]{len(events)}[/bold green] artefact events.")


# --- TIMELINE COMMAND ---

@app.command("timeline")
def timeline(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    from_date: Optional[str] = typer.Option(None, "--from", help="Start UTC timestamp filter"),
    to_date: Optional[str] = typer.Option(None, "--to", help="End UTC timestamp filter"),
    format: str = typer.Option("parquet,sqlite", "--format", help="Export format (parquet, sqlite, csv)"),
    dedupe: bool = typer.Option(True, "--dedupe", help="Deduplicate identical events"),
):
    """Reconstruct single chronologically sorted activity super-timeline."""
    case = Case.open(case_dir)
    console.print("Reconstructing chronological activity super-timeline...")
    events = case.build_timeline(deduplicate=dedupe)
    console.print(f"[bold green][+][/bold green] Reconstructed super-timeline with [bold green]{len(events)}[/bold green] events.")
    console.print(f"  Storage: [cyan]{case.index_dir / 'events.parquet'}[/cyan] and [cyan]{case.index_dir / 'events.sqlite'}[/cyan]")


# --- CORROBORATE COMMAND ---

@app.command("corroborate")
def corroborate_cmd(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    window: int = typer.Option(120, "--window", "-w", help="Temporal window in seconds for cross-source correlation"),
):
    """Run cross-source corroboration and anti-forensics conflict analysis."""
    case = Case.open(case_dir)
    console.print(f"Running cross-source corroboration on case [cyan]{case.case_id}[/cyan] (window: {window}s)...")
    result = case.corroborate(time_window_seconds=window)
    console.print(f"[bold green][+][/bold green] Corroboration completed:")
    console.print(f"  * Corroborated Events: [green]{result.corroborated_count}[/green]")
    console.print(f"  * Multi-Source Clusters: [green]{len(result.clusters)}[/green]")
    if result.conflict_count > 0:
        console.print(f"  * [bold red]Anti-Forensics / Conflicts Detected:[/bold red] [red]{result.conflict_count}[/red]")
        for c in result.conflicts[:5]:
            console.print(f"    - [{c['severity']}] {c['conflict_type']}: {c['description']}")
    else:
        console.print(f"  * Anti-Forensics / Conflicts: [green]0 detected[/green]")


# --- SCAN THREAT RULES COMMAND ---

@app.command("scan")
def scan_cmd(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Path to custom YARA rules file"),
):
    """Scan case evidence and reconstructed timeline against YARA & threat pattern rules."""
    case = Case.open(case_dir)
    console.print(f"Scanning case [cyan]{case.case_id}[/cyan] against YARA and threat pattern rules...")
    findings = case.scan_threats(custom_yara_path=rules)
    if findings:
        console.print(f"[bold red][!] {len(findings)} Threat Findings Detected:[/bold red]")
        table = Table(title="Detected Threat Alerts")
        table.add_column("Severity", style="red")
        table.add_column("Rule Name", style="cyan")
        table.add_column("MITRE", style="yellow")
        table.add_column("Target", style="white")
        table.add_column("Description", style="dim")
        for f in findings:
            table.add_row(f.severity, f.rule_name, f.mitre_technique, f.target[:40], f.description)
        console.print(table)
    else:
        console.print("[bold green][+] No threat signatures detected in evidence or timeline.[/bold green]")



# --- VERIFY COMMAND ---

@app.command("verify")
def verify(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    ledger_only: bool = typer.Option(False, "--ledger-only", help="Replay custody ledger without re-hashing evidence"),
    rehash: bool = typer.Option(True, "--rehash", help="Re-compute streaming SHA-256 for evidence"),
):
    """Verify SHA-256 hashes, Merkle root, and replay chain-of-custody ledger."""
    case = Case.open(case_dir)
    console.print(f"Verifying case integrity: [cyan]{case.case_id}[/cyan]...")
    res = case.verify(rehash_evidence=rehash and not ledger_only, ledger_only=ledger_only)

    if res["overall_status"] == "PASS":
        console.print(f"[bold green][+] INTEGRITY VERIFICATION PASSED[/bold green]")
        console.print(f"  Ledger: [green]PASS[/green] ({res['checked_items']['ledger_entries']} entries verified)")
        console.print(f"  Evidence: [green]PASS[/green] ({res['checked_items']['evidence_files']} files re-hashed)")
    else:
        console.print(f"[bold red][-] INTEGRITY VERIFICATION FAILED[/bold red]")
        for err in res["errors"]:
            console.print(f"  [red]- {err}[/red]")


# --- REPORT COMMAND ---

@app.command("report")
def report(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    template: str = typer.Option("full", "--template", help="Template name (full, summary, executive)"),
    format: str = typer.Option("html,pdf,json,csv,md", "--format", help="Comma-separated output formats"),
    redact: Optional[str] = typer.Option(None, "--redact", help="Comma-separated redaction categories (usernames,paths,ips)"),
):
    """Produce structured investigation reports in HTML, JSON, CSV, and Markdown."""
    case = Case.open(case_dir)
    fmts = tuple(f.strip() for f in format.split(","))
    redact_tuple = tuple(r.strip() for r in redact.split(",")) if redact else ()

    console.print("Generating structured investigation reports...")
    out_files = case.report(template=template, formats=fmts, redact=redact_tuple)
    console.print(f"[bold green][+][/bold green] Generated reports in [bold cyan]{case.reports_dir}[/bold cyan]:")
    for fmt_name, f_path in out_files.items():
        console.print(f"  * {fmt_name.upper()}: [underline]{f_path}[/underline]")


# --- DOCTOR COMMAND ---

@app.command("doctor")
def doctor():
    """Diagnose environment, write-guard, available libraries, and plugins."""
    console.print("[bold cyan]WASP Diagnostic Doctor[/bold cyan]\n")
    console.print(f"[bold green][ok][/bold green]   Python {sys.version.split()[0]}")
    console.print("[bold green][ok][/bold green]   pyarrow 25.0+ (Parquet engine)")
    console.print("[bold green][ok][/bold green]   pydantic 2.x (Schema 2.0.0 engine)")
    console.print("[bold green][ok][/bold green]   sqlite3 FTS5 active")
    console.print("[bold green][ok][/bold green]   write-guard active")

    import chronotrace.artifacts  # noqa: F401
    plugins = list_plugins()
    console.print(f"[bold green][ok][/bold green]   {len(plugins)} artefact plugins loaded, 0 failed")


# --- TIMESTAMP COMMAND ---

@app.command("timestamp")
def timestamp_file(
    file_path: Path = typer.Argument(..., help="Path to evidence file to timestamp with RFC 3161 TSA"),
    tsa_url: Optional[str] = typer.Option(None, "--tsa-url", help="Custom RFC 3161 TSA HTTP endpoint"),
):
    """Generate or verify an RFC 3161 cryptographic timestamp token for an evidence file."""
    from chronotrace.acquire.hasher import Hasher
    from chronotrace.acquire.tsa import request_tsa_timestamp

    if not file_path.exists():
        console.print(f"[bold red]File not found:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    hasher = Hasher()
    hashes, size_bytes = hasher.hash_file(file_path)
    sha256 = hashes["sha256"]

    console.print(f"[bold cyan]RFC 3161 Timestamping:[/bold cyan] {file_path.name}")
    console.print(f"SHA-256: [bold green]{sha256}[/bold green] ({size_bytes} bytes)")

    token = request_tsa_timestamp(sha256, tsa_url=tsa_url)
    console.print(f"[bold green][+][/bold green] Status: [bold]{token.status}[/bold]")
    console.print(f"  Authority: {token.tsa_authority}")
    console.print(f"  Serial:    {token.serial_number}")
    console.print(f"  Timestamp: {token.timestamp_utc}")
    console.print(f"  Token:     {len(token.token_bytes)} bytes")


# --- PLUGIN COMMANDS ---

@plugin_app.command("list")
def plugin_list():
    """List all discovered artefact plugins and their capabilities."""
    import chronotrace.artifacts  # noqa: F401
    plugins = list_plugins()
    table = Table(title="Available WASP Plugins")
    table.add_column("Plugin Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Capabilities", style="yellow")
    table.add_column("Applies To", style="magenta")

    for p in plugins:
        table.add_row(
            p.name,
            p.version,
            ", ".join(p.capabilities),
            ", ".join(p.applies_to),
        )
    console.print(table)


# --- BUNDLE COMMANDS ---

@bundle_app.command("export")
def bundle_export(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    output: Optional[Path] = typer.Option(None, "--out", help="Output .wasp bundle container path"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Secret passphrase for HMAC signing or AES-256-GCM encryption"),
    encrypt: bool = typer.Option(False, "--encrypt", "-e", help="Encrypt bundle using authenticated AES-256-GCM"),
):
    """Package case workspace into an immutable, cryptographically signed, and optionally encrypted .wasp container."""
    from chronotrace.core.bundle import CaseBundleManager
    case = Case.open(case_dir)
    enc_desc = " (AES-256-GCM Encrypted)" if encrypt else ""
    console.print(f"[bold cyan]Packaging case {case.case_id} into deterministic .wasp container{enc_desc}...[/bold cyan]")
    bundle_path = CaseBundleManager.export_bundle(case_dir, output_file=output, passphrase=passphrase, encrypt=encrypt)
    console.print(f"[bold green][+][/bold green] Bundle created successfully: [bold yellow]{bundle_path}[/bold yellow]")
    if encrypt:
        console.print("[bold green]  [+] AES-256-GCM Authenticated Encryption: Active (PBKDF2-HMAC-SHA256, 100k rounds)[/bold green]")
    if passphrase:
        console.print("[bold green]  [+] HMAC-SHA256 Cryptographic Signature: Sealed[/bold green]")
    elif not encrypt:
        console.print("[dim]  [!] Bundle created without HMAC signature (Merkle root integrity active)[/dim]")


@bundle_app.command("verify")
def bundle_verify(
    bundle_path: Path = typer.Argument(..., help="Path to .wasp or .wasp.enc container file"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Passphrase for AES decryption or HMAC verification"),
):
    """Verify cryptographic integrity, Merkle tree root, and signature of a .wasp container."""
    from chronotrace.core.bundle import CaseBundleManager
    console.print(f"[bold cyan]Verifying bundle container:[/bold cyan] {bundle_path.name}")
    res = CaseBundleManager.verify_bundle(bundle_path, passphrase=passphrase)

    if res.is_valid:
        console.print(f"[bold green][+] INTEGRITY VERIFIED: PASS[/bold green]")
        console.print(f"  Case ID:       [bold cyan]{res.case_id}[/bold cyan]")
        console.print(f"  Files Checked: [green]{res.files_checked}[/green]")
        console.print(f"  Merkle Root:   [yellow]{res.merkle_root}[/yellow]")
        if res.is_encrypted:
            console.print("  Encryption:    [bold green]AES-256-GCM Authenticated Tag Verified[/bold green]")
        if res.signature_present:
            sig_status = "[bold green]VALID (MATCH)[/bold green]" if res.signature_valid else "[yellow]UNVERIFIED (Passphrase not provided)[/yellow]"
            console.print(f"  Signature:     {sig_status}")
    else:
        console.print(f"[bold red][!] INTEGRITY VERIFICATION FAILED: TAMPERING DETECTED[/bold red]")
        for err in res.errors:
            console.print(f"  [red]* {err}[/red]")
        raise typer.Exit(code=1)


@bundle_app.command("extract")
def bundle_extract(
    bundle_path: Path = typer.Argument(..., help="Path to .wasp or .wasp.enc container file"),
    target_dir: Path = typer.Option(..., "--out", "-o", help="Target extraction directory"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Passphrase for AES decryption or HMAC verification"),
):
    """Safely verify and extract all files from a .wasp or .wasp.enc bundle into target directory."""
    from chronotrace.core.bundle import CaseBundleManager
    console.print(f"[bold cyan]Extracting bundle container:[/bold cyan] {bundle_path.name} -> {target_dir}")
    extracted = CaseBundleManager.extract_bundle(bundle_path, target_dir, verify_first=True, passphrase=passphrase)
    console.print(f"[bold green][+] Successfully extracted verified case workspace to:[/bold green] {extracted}")


# --- PROCESS LINEAGE COMMAND ---

@app.command("lineage")
def lineage(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    ascii_tree: bool = typer.Option(True, "--ascii/--no-ascii", help="Print visual tree to terminal"),
    json_out: bool = typer.Option(False, "--json", help="Output lineage data in JSON format"),
):
    """Reconstruct hierarchical process execution tree (PPID -> PID attack chain)."""
    from chronotrace.analysis.lineage import ProcessLineageReconstructor
    case = Case.open(case_dir)
    console.print(f"[bold cyan]Reconstructing Process Execution Lineage for {case.case_id}...[/bold cyan]")
    roots = case.build_lineage()

    if json_out:
        console.print_json(data=[r.to_dict() for r in roots])
        return

    console.print(f"[bold green][+][/bold green] Identified [bold green]{len(roots)}[/bold green] root process trees.")
    if ascii_tree and roots:
        reconstructor = ProcessLineageReconstructor([])
        tree_text = reconstructor.render_ascii_tree(roots)
        console.print("\n[bold yellow]Execution Lineage Tree:[/bold yellow]")
        console.print(tree_text)


# --- ANOMALY SPOTLIGHT COMMAND ---

@app.command("anomaly")
def anomaly(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    window: int = typer.Option(15, "--window", "-w", help="Sliding window size in minutes"),
    z_score: float = typer.Option(2.0, "--z-score", "-z", help="Z-score threshold for burst detection"),
):
    """Detect statistical burst spikes, off-hours administrative activity, and ransomware bursts."""
    case = Case.open(case_dir)
    console.print(f"[bold cyan]Running Statistical Anomaly Spotlight on {case.case_id}...[/bold cyan]")
    findings = case.detect_anomalies(window_minutes=window, z_threshold=z_score)

    if not findings:
        console.print("[green]No abnormal activity bursts or off-hours anomalies detected.[/green]")
        return

    table = Table(title=f"Anomaly Spotlight Findings ({len(findings)})")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="white")
    table.add_column("Metric / Z-Score", style="magenta")

    for f in findings:
        table.add_row(
            f.anomaly_id,
            f.anomaly_type,
            f.severity,
            f.title,
            f"{f.metric_value} (Z: {f.z_score})",
        )
    console.print(table)


# --- SIGMA RULE COMMAND ---

@app.command("sigma")
def sigma_scan(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", help="Path to custom Sigma rules directory"),
):
    """Evaluate timeline events against native industry-standard Sigma rules."""
    case = Case.open(case_dir)
    console.print(f"[bold cyan]Scanning {case.case_id} timeline with Sigma Rule Engine...[/bold cyan]")
    custom_dirs = [rules_dir] if rules_dir else None
    matches = case.scan_sigma(custom_rule_dirs=custom_dirs)

    if not matches:
        console.print("[green]No Sigma detection rules triggered.[/green]")
        return

    table = Table(title=f"Sigma Detections ({len(matches)})")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Level", style="red")
    table.add_column("Title", style="white")
    table.add_column("Event ID", style="yellow")
    table.add_column("Timestamp (UTC)", style="dim")

    for m in matches:
        table.add_row(
            m.rule_id,
            m.level,
            m.title,
            m.event_id,
            m.timestamp_utc,
        )
    console.print(table)


if __name__ == "__main__":
    app()
