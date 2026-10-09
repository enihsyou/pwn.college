"""Start the next pwn.college challenge; Task then initializes its solution."""

from rich.console import Console
from rich.live import Live

from scripts import pwn_college_api as api

console = Console()


def challenge_url(context: dict) -> str:
    return "https://pwn.college/{dojo}/{module}/{challenge}".format(**context)


def main() -> int:
    try:
        client = api.PwnCollegeApi(api.read_access_token())
        context = client.next_challenge()
        url = challenge_url(context)

        with Live(f"Next challenge: {url}", console=console, transient=False) as live:
            client.start_challenge(context)
            live.update(f"[bold green]Challenge started:[/] {url}")
        return 0
    except api.ApiError as error:
        console.print(f"[bold red]Error:[/] {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
