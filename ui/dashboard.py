from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime

console = Console()

class EnterpriseSOCDashboard:
    """
    Renders high-fidelity telemetry tracking grids modeling live proxy decisions.
    """
    @staticmethod
    def print_gateway_header():
        console.print(Panel.fit(
            "🛰️  [bold green]NOVAGATE-AISHIELD[/bold green] : [bold white]ENTERPRISE INTERCEPT GATEWAY SUITE v2.0[/bold white]",
            subtitle="Asynchronous Security Telemetry Matrix Active",
            border_style="green"
        ))

    @staticmethod
    def render_triage_packet(raw_payload: str, normalization: dict, metrics: dict):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        table = Table(title=f"🚨 SECURITY INSPECTION TRAFFIC METRIC — {timestamp}", title_style="bold yellow", show_lines=True)
        table.add_column("Security Infrastructure Matrix Key", style="green", width=30)
        table.add_column("Monitored Telemetry Runtime Value", style="white")

        table.add_row("Ingested Raw String", raw_payload[:90] + ("..." if len(raw_payload) > 90 else ""))
        table.add_row("Stripped Obfuscation Layers", ", ".join(normalization["pipeline_telemetry"]) if normalization["pipeline_telemetry"] else "None (Clear Stream)")
        table.add_row("Normalized System State", normalization["processed_string"][:90])
        table.add_row("Payload Shannon Complexity", f"Entropy Index: {metrics['entropy_score']}")
        table.add_row("Semantic Target Correlation", f"Vector Distance: {metrics['vector_proximity']} / 10.0")
        
        risk = metrics["calculated_risk_index"]
        color = "red" if risk >= 6.5 else "yellow" if risk >= 4.5 else "green"
        table.add_row("Calculated Risk Score", f"[{color}][bold]{risk} / 10.0[/bold][/{color}]")
        table.add_row("Triggered Threat Signatures", ", ".join(metrics["signatures_triggered"]) if metrics["signatures_triggered"] else "Clear")
        
        verdict = metrics["verdict"]
        verdict_str = f"[bold white on red] 🚨 ACTION BLOCKED: DISALLOWED PACKET METRIC [/bold white on red]" if verdict == "REJECT" else f"[bold black on green] ✅ PIPELINE UNLOCKED: SECURE STREAM PASSED [/bold black on green]"
        table.add_row("Automated Proxy Action", verdict_str)
        
        console.print(table)
        console.print("\n")
