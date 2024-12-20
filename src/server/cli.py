import click
from .api import LicenseServer
from .config import ServerConfig

@click.group()
def cli():
    """CLI tool cho License Server"""
    pass

@cli.command()
@click.option('--host', default='0.0.0.0', help='Server host')
@click.option('--port', default=5000, help='Server port')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def run(host, port, debug):
    """Khởi động license server"""
    config = ServerConfig(host=host, port=port, debug=debug)
    server = LicenseServer(config)
    server.run()

@cli.command()
@click.argument('api_key')
def verify(api_key):
    """Kiểm tra license key"""
    config = ServerConfig.load_from_env()
    manager = LicenseManager(config.secret_key)
    is_valid = manager.verify_license(api_key)
    click.echo(f"License {'valid' if is_valid else 'invalid'}") 