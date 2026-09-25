from collections.abc import Iterable, Iterator
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
import yara
from rich.console import Console
from rich.text import Text

from yara_scout.models import ScanResult
from yara_scout.reporting import JsonReporter, TerminalReporter
from yara_scout.scanner import DEFAULT_MAX_FILE_SIZE, DEFAULT_TIMEOUT, Scanner


if TYPE_CHECKING:
    from yara_scout.validation import ValidationReport


app = typer.Typer(
    name="yara-scout",
    help="Inspect files with YARA rules and produce triage findings.",
    no_args_is_help=True,
)


def show_version(value: bool) -> None:
    """Print the installed package version and stop command processing."""
    if value:
        typer.echo(version("yara-scout"))
        raise typer.Exit()


def capture_results(
    results: Iterable[ScanResult],
    captured: list[ScanResult],
) -> Iterator[ScanResult]:
    """Yield results to the terminal reporter while retaining them for JSON."""
    for result in results:
        captured.append(result)
        yield result


def validation_path(path: Path, report: "ValidationReport") -> str:
    """Return a concise path relative to the validated rule root."""
    if report.rule_path.is_file():
        return path.name
    try:
        return path.relative_to(report.rule_path).as_posix()
    except ValueError:
        return path.name


def print_validation_report(
    report: "ValidationReport",
    console: Console,
) -> None:
    """Render validation findings and their aggregate counts."""
    for finding in report.findings:
        location = validation_path(finding.path, report)
        if finding.line is not None:
            location = f"{location}:{finding.line}"

        message = Text("[INVALID] ", style="bold red")
        message.append(location)
        if finding.rule is not None:
            message.append(f" ({finding.rule})")
        message.append(f": {finding.message}")
        console.print(message)

    status = "passed" if report.valid else "failed"
    style = "bold green" if report.valid else "bold red"
    summary = Text(f"Validation {status}: ", style=style)
    summary.append(
        f"{report.files_checked} file(s), "
        f"{report.rules_checked} rule(s), "
        f"{len(report.findings)} finding(s)."
    )
    console.print(summary)


@app.callback()
def main(
    version_requested: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=show_version,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = False,
) -> None:
    """YARA-based file triage from the command line."""


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="File or directory to scan.",
            exists=True,
            readable=True,
            resolve_path=False,
        ),
    ],
    rules: Annotated[
        Path,
        typer.Option(
            "--rules",
            "-r",
            help="YARA rule file or directory.",
            exists=True,
            readable=True,
            resolve_path=True,
        ),
    ],
    matches_only: Annotated[
        bool,
        typer.Option(
            "--matches-only",
            "-m",
            help="Hide clean-file details while keeping them in the summary.",
        ),
    ] = False,
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            "-t",
            min=1,
            help="Maximum YARA matching time per file, in seconds.",
        ),
    ] = DEFAULT_TIMEOUT,
    max_file_size_mb: Annotated[
        int,
        typer.Option(
            "--max-file-size-mb",
            "-s",
            min=1,
            help="Skip files larger than this size, in MiB.",
        ),
    ] = DEFAULT_MAX_FILE_SIZE // (1024 * 1024),
    follow_symlinks: Annotated[
        bool,
        typer.Option(
            "--follow-symlinks",
            "-L",
            help="Scan files reached through symbolic links.",
        ),
    ] = False,
    json_output: Annotated[
        Path | None,
        typer.Option(
            "--json",
            "-j",
            help="Write a complete JSON report to this path.",
            dir_okay=False,
            resolve_path=False,
        ),
    ] = None,
) -> None:
    """Scan a file or directory with a collection of YARA rules."""
    console = Console()
    captured_results: list[ScanResult] = []

    try:
        scanner = Scanner(
            rules,
            timeout=timeout,
            max_file_size=max_file_size_mb * 1024 * 1024,
            follow_symlinks=follow_symlinks,
        )
        results: Iterable[ScanResult] = scanner.scan(target)
        if json_output is not None:
            results = capture_results(results, captured_results)

        summary = TerminalReporter(console).report(
            results,
            matches_only=matches_only,
        )
    except (OSError, ValueError, yara.Error) as error:
        message = Text("Unable to start scan: ", style="bold red")
        message.append(str(error))
        Console(stderr=True).print(message)
        raise typer.Exit(code=2) from error

    if json_output is not None:
        try:
            JsonReporter().write(
                json_output,
                target=target,
                results=captured_results,
                summary=summary,
                timeout=timeout,
                max_file_size=max_file_size_mb * 1024 * 1024,
                follow_symlinks=follow_symlinks,
            )
        except OSError as error:
            message = Text("Unable to write JSON report: ", style="bold red")
            message.append(str(error))
            Console(stderr=True).print(message)
            raise typer.Exit(code=2) from error

    if summary.errors:
        raise typer.Exit(code=1)


@app.command()
def validate(
    rules: Annotated[
        Path,
        typer.Argument(
            help="YARA rule file or directory to validate.",
            resolve_path=False,
        ),
    ],
) -> None:
    """Compile rules and check the YARA Scout authoring convention."""
    from yara_scout.validation import RuleValidator

    console = Console()

    try:
        report = RuleValidator().validate(rules)
    except (OSError, ValueError) as error:
        message = Text("Unable to start validation: ", style="bold red")
        message.append(str(error))
        Console(stderr=True).print(message)
        raise typer.Exit(code=2) from error

    print_validation_report(report, console)
    if not report.valid:
        raise typer.Exit(code=1)
