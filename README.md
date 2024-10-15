# Protection Helper Bot

This script helps manage protection levels on English Wikipedia by automatically restoring edit and move protections when appropriate after a temporary higher-level protection expires.

## Features

- Monitor the protection log for temporary higher protection levels and their expirations.
- After expiration, check the page protection status and restore the previous protection if needed.
- Log protection changes with the appropriate reason and attribution.

## Dependencies

To run the `reprotect.py` script, you'll need the following:

- `Python`: Version 3.10 or later is strongly recommended.
- `pywikibot`: A Python package that allows bots to interact with MediaWiki sites, version 9.3.1 or later is required.
- `supervisor`: To run and manage the bot in production (not a requirement but recommended for production environments).

## Installation

1. Clone the repository and navigate into the project directory:
```
git clone https://github.com/danielquinlan/protection-helper-bot.git
cd protection-helper-bot
```

2. Install Pywikibot:
```
pip3 install pywikibot
```

3. Install the script:
```
pip3 install .
```

## Configuration

You'll need to configure Pywikibot to interact with your MediaWiki site. Typically, this involves setting up `user-config.py` for Pywikibot and adding site-specific information. The script has not been tested on other MediaWiki sites and would likely require modifications to run anywhere other than English Wikipedia, particularly the protection levels.

## Running in Test Mode

For testing purposes, you can run the bot in "dry run" mode (the default), which simulates the process without performing any administrative actions. There are also options to run simulations on past log data.

### Command-line options

- `--backtest`: Simulate past protection expirations. Use this for testing with logs from the past.
- `--future <days>`: Simulate protections that will expire within a specified number of future days.

To run the bot in test mode:
```
python3 reprotect.py --backtest
```

Or for simulating future days:
```
python3 reprotect.py --future 30
```

## Running in production

In production, you'll want to disable the dry run mode. To do this, set the environment variable `REPROTECT_DRY_RUN` to "false".

You can run the bot continuously using Supervisor, a process control system that keeps the bot running and automatically restarts it if it exits unexpectedly.

### Supervisor configuration

This is an example Supervisor 4.2.x configuration file (`/etc/supervisor/conf.d/reprotect.conf`):

```
[program:reprotect]
environment=HOME="/home/youruser",YOURUSER="youruser",PYWIKIBOT_DIR="/home/youruser/.config/pywikibot/yourbotconfiguration",REPROTECT_DRY_RUN="false"
directory=/home/youruser
user=youruser
command=/home/youruser/yourscriptdirectory/reprotect.py
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/reprotect.log
startretries=288
```

This configuration will:

- Start the bot as the specified user.
- Automatically restart the bot if it crashes.
- Log output to `/var/log/reprotect.log`.

## Additional documentation

For further details, please refer to the additional documentation located in [scripts/reprotect.py](scripts/reprotect.py).

## License

This project is licensed under the [GPL-3.0 license](LICENSE).
