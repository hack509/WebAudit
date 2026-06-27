"""
WebAudit — Professional Web Application Auditing Tool.

Usage:
    python main.py                          # Interactive menu
    python main.py --url https://example.com  # Direct audit
    python main.py --config config.json     # Use config file

Author: WebAudit Team
License: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm

from config.settings import AuditConfig
from audit.runner import AuditRunner
from reports.generator import ReportGenerator
from utils.logger import setup_logger, get_logger
from utils.constants import APP_NAME, APP_VERSION, APP_DESCRIPTION

console = Console()


BANNER = r"""
[bold cyan]
 ██╗    ██╗███████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║  ██║██║   ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║  ██║██║   ██║
 ╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
[/bold cyan]
[dim]Professional Web Application Auditing Tool v{version}[/dim]
""".format(version=APP_VERSION)


MENU_OPTIONS = {
    1: ("Audit complet", "full"),
    2: ("Audit Backend", "backend"),
    3: ("Audit Frontend", "frontend"),
    4: ("Audit API", "api"),
    5: ("Audit Sécurité", "security"),
    6: ("Audit Performance", "performance"),
    7: ("Audit UX", "ux"),
    8: ("Audit JavaScript", "javascript"),
    9: ("Audit Mobile", "mobile"),
    10: ("Audit Authentification", "auth"),
    11: ("Audit Base de données", "database"),
    12: ("Tests End-to-End", "e2e"),
    13: ("Captures d'écran", "screenshots"),
    14: ("Générer rapport", "report"),
    15: ("Configuration", "config"),
    0: ("Quitter", "quit"),
}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="webaudit",
        description=f"{APP_NAME} v{APP_VERSION} — {APP_DESCRIPTION}",
    )
    parser.add_argument("--url", type=str, help="Target URL to audit")
    parser.add_argument(
        "--urls", type=str, nargs="+", metavar="URL",
        help="Multiple target URLs to audit in parallel",
    )
    parser.add_argument("--source", type=str, help="Path to source code directory")
    parser.add_argument(
        "--serve", action="store_true",
        help="Start the WebAudit REST API + dashboard server",
    )
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="API server port (default: 8000)")
    parser.add_argument("--token", type=str, help="JWT token for authenticated requests")
    parser.add_argument("--user", type=str, help="Username for auth tests")
    parser.add_argument("--password", type=str, help="Password for auth tests")
    parser.add_argument("--config", type=str, help="Path to JSON configuration file")
    parser.add_argument("--output", type=str, default="reports", help="Report output directory")
    parser.add_argument(
        "--format", type=str, nargs="+",
        default=["html", "json"],
        choices=["html", "pdf", "json", "csv", "markdown"],
        help="Report formats to generate",
    )
    parser.add_argument("--module", type=str, nargs="+", help="Specific modules to run")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--lang", type=str, default="fr", choices=["fr", "en"], help="Report language")
    parser.add_argument(
        "--accept-tos", action="store_true",
        help="Confirm you have authorization to test the target (required in non-interactive mode)",
    )
    parser.add_argument(
        "--profile", type=str, choices=["dev", "staging", "prod", "ci"],
        help="Load a named configuration profile (dev/staging/prod/ci)",
    )

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> AuditConfig:
    """Build AuditConfig from profile → JSON file → CLI args → env vars (increasing priority)."""
    # 1. Start from profile (lowest priority)
    if getattr(args, "profile", None):
        config = AuditConfig.from_profile(args.profile)
    else:
        config = AuditConfig()

    # 2. JSON file overrides profile
    if args.config:
        config = AuditConfig.from_json(args.config)

    # Override with CLI args
    if args.url:
        config.target.url = args.url
    if args.source:
        config.target.source_dir = args.source
    if args.token:
        config.auth.jwt_token = args.token
    if args.user:
        config.auth.username = args.user
    if args.password:
        config.auth.password = args.password
    if args.output:
        config.report.output_dir = args.output
    if args.format:
        config.report.formats = args.format
    if args.verbose:
        config.verbose = True
    if args.lang:
        config.report.language = args.lang

    # 4. Environment variables (highest priority — useful in CI)
    config.apply_env_overrides()

    return config


def show_menu() -> int:
    """Display the interactive menu and return the selected option."""
    console.print()
    console.print(
        Panel(
            "\n".join(
                f"  [cyan]{k:>2}[/cyan]  {v[0]}"
                for k, v in sorted(MENU_OPTIONS.items())
                if k != 0
            ) + "\n\n  [red] 0[/red]  Quitter",
            title="[bold magenta]📋 Menu Principal[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )

    choice = IntPrompt.ask(
        "[bold cyan]Votre choix[/bold cyan]",
        choices=[str(k) for k in MENU_OPTIONS.keys()],
        default=1,
    )
    return choice


def show_legal_disclaimer() -> bool:
    """Display a legal disclaimer and require explicit user confirmation.

    Returns True if the user accepts, False otherwise.
    """
    console.print()
    console.print(
        Panel(
            "[bold yellow]AVERTISSEMENT LÉGAL / LEGAL WARNING[/bold yellow]\n\n"
            "[white]WebAudit effectue des tests actifs (requêtes HTTP, injections de test,\n"
            "crawl automatique) sur la cible spécifiée.\n\n"
            "⚠️  UTILISER UNIQUEMENT SUR DES SYSTÈMES QUE VOUS POSSÉDEZ\n"
            "    OU POUR LESQUELS VOUS AVEZ UNE AUTORISATION ÉCRITE EXPLICITE.\n\n"
            "L'utilisation non autorisée sur des systèmes tiers est illégale\n"
            "et engage votre responsabilité pénale et civile.\n\n"
            "[dim]WebAudit performs active tests (HTTP requests, test payloads, crawling)\n"
            "on the specified target. Use only on systems you own or have explicit\n"
            "written authorization to test.[/dim][/white]",
            title="[bold red]⚠️  Conditions d'utilisation[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    confirmed = Confirm.ask(
        "[bold]Je confirme avoir l'autorisation de tester cette cible[/bold]",
        default=False,
    )

    if not confirmed:
        console.print("\n[red]Audit annulé — autorisation non confirmée.[/red]\n")

    return confirmed


def prompt_url(config: AuditConfig) -> AuditConfig:
    """Prompt for the target URL if not set."""
    if not config.target.url or config.target.url == "http://localhost:3000":
        url = Prompt.ask(
            "[bold cyan]URL cible[/bold cyan]",
            default="http://localhost:3000",
        )
        config.target.url = url
    return config


async def run_multi_targets(
    urls: list[str],
    base_config: AuditConfig,
    modules: list[str] | None = None,
) -> None:
    """Run audits for multiple URLs in parallel and summarise results."""
    console.print(f"\n[bold cyan]Multi-target audit — {len(urls)} cibles[/bold cyan]")

    async def _audit_one(url: str) -> tuple[str, float | None, str | None]:
        cfg = base_config.model_copy(deep=True)
        cfg.target.url = url
        runner = AuditRunner(cfg)
        runner.register_all_auditors()
        try:
            report = await (runner.run_selected(modules) if modules else runner.run_all())
            return url, report.global_score, report.global_grade
        except Exception as e:
            console.print(f"[red]  ✗ {url}: {e}[/red]")
            return url, None, None

    results = await asyncio.gather(*[_audit_one(u) for u in urls])

    console.print()
    for url, score, grade in results:
        if score is not None:
            color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
            console.print(f"  [{color}]{grade} {score:.1f}/100[/{color}]  {url}")
        else:
            console.print(f"  [red]FAIL[/red]  {url}")


async def run_audit(config: AuditConfig, modules: list[str] | None = None) -> None:
    """Run the audit with the given configuration."""
    runner = AuditRunner(config)
    runner.register_all_auditors()

    if modules:
        report = await runner.run_selected(modules)
    else:
        report = await runner.run_all()

    # Generate reports
    if report:
        report_gen = ReportGenerator(config.report)
        generated = report_gen.generate_all(report)

        if generated:
            console.print()
            console.print(
                Panel(
                    "\n".join(f"  📄 {f}" for f in generated),
                    title="[bold green]📊 Rapports générés[/bold green]",
                    border_style="green",
                )
            )


async def run_interactive(config: AuditConfig) -> None:
    """Run the interactive menu loop."""
    console.print(BANNER)

    if not show_legal_disclaimer():
        return

    config = prompt_url(config)

    console.print(f"[dim]Cible: {config.target.url}[/dim]")

    while True:
        choice = show_menu()

        if choice == 0:
            console.print("\n[bold cyan]👋 Au revoir ![/bold cyan]\n")
            break

        option = MENU_OPTIONS.get(choice)
        if not option:
            console.print("[red]Option invalide[/red]")
            continue

        label, action = option

        if action == "quit":
            console.print("\n[bold cyan]👋 Au revoir ![/bold cyan]\n")
            break
        elif action == "full":
            await run_audit(config)
        elif action == "report":
            # Re-run full audit and generate all reports
            config.report.formats = ["html", "pdf", "json", "csv", "markdown"]
            await run_audit(config)
        elif action == "config":
            # Show current config
            console.print(
                Panel(
                    f"URL: {config.target.url}\n"
                    f"API Base: {config.target.api_base}\n"
                    f"Source: {config.target.source_dir}\n"
                    f"JWT: {'✅' if config.auth.jwt_token else '❌'}\n"
                    f"User: {config.auth.username or '—'}\n"
                    f"DB: {config.database.connection_string or '—'}\n"
                    f"Formats: {', '.join(config.report.formats)}\n"
                    f"Langue: {config.report.language}\n"
                    f"Modules: {', '.join(config.modules_enabled)}",
                    title="[bold cyan]⚙️  Configuration[/bold cyan]",
                    border_style="cyan",
                )
            )

            # Allow URL change
            new_url = Prompt.ask(
                "Nouvelle URL (Entrée pour garder)",
                default=config.target.url,
            )
            config.target.url = new_url

        else:
            # Run specific module
            modules_to_run = ["discovery", action]
            await run_audit(config, modules_to_run)


def main() -> None:
    """Main entry point."""
    args = parse_args()
    config = build_config(args)

    # Setup logging
    setup_logger(verbose=config.verbose)
    logger = get_logger("main")

    # Create output directories
    Path("logs").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    Path("screenshots").mkdir(exist_ok=True)

    try:
        if getattr(args, "serve", False):
            # Start API server + dashboard
            console.print(BANNER)
            console.print(
                Panel(
                    f"[bold]WebAudit API server[/bold]\n\n"
                    f"  Dashboard : [cyan]http://{args.host}:{args.port}/[/cyan]\n"
                    f"  API docs  : [cyan]http://{args.host}:{args.port}/api/docs[/cyan]\n"
                    f"  Redoc     : [cyan]http://{args.host}:{args.port}/api/redoc[/cyan]",
                    title="[bold green]🚀 Lancement du serveur[/bold green]",
                    border_style="green",
                )
            )
            import uvicorn
            from api.app import app
            uvicorn.run(app, host=args.host, port=args.port)
            return

        # Multi-target mode
        urls = getattr(args, "urls", None)
        if urls:
            if not getattr(args, "accept_tos", False):
                console.print(BANNER)
                if not show_legal_disclaimer():
                    sys.exit(0)
            asyncio.run(run_multi_targets(urls, config, args.module))
            return

        if args.url and not sys.stdin.isatty():
            # Non-interactive (CI/pipeline): skip disclaimer, user must set --accept-tos
            if not getattr(args, "accept_tos", False):
                console.print(
                    "[red]En mode non-interactif, ajoutez --accept-tos pour confirmer "
                    "que vous avez l'autorisation de tester cette cible.[/red]"
                )
                sys.exit(1)
            logger.info(f"Starting audit for {config.target.url}")
            modules = args.module if args.module else None
            asyncio.run(run_audit(config, modules))
        elif args.url:
            # URL provided, interactive terminal — show disclaimer once
            console.print(BANNER)
            if not show_legal_disclaimer():
                sys.exit(0)
            asyncio.run(run_audit(config, args.module))
        else:
            # Interactive menu (disclaimer shown inside run_interactive)
            asyncio.run(run_interactive(config))

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Audit interrompu par l'utilisateur[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[red bold]❌ Erreur fatale: {e}[/red bold]")
        sys.exit(1)


if __name__ == "__main__":
    main()
