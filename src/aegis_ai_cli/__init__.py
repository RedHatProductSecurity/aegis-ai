"""
aegis cli

"""

from aegis_ai import __version__


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    print(f"Aegis-AI v{__version__}, https://github.com/RedHatProductSecurity/aegis-ai")
    ctx.exit()
