# cli.py
import click
from scanner.scanner import scan_file
from scanner.reporter import report

@click.command()
@click.argument('config_file', type=click.Path(exists=True))
def cli(config_file):
    """Scan a cloud config file for misconfigurations."""
    findings = scan_file(config_file)
    report(findings)

if __name__ == '__main__':
    cli()