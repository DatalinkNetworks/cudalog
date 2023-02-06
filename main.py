from argparse import ArgumentParser
from cudalog.firewall import NGFW
from cudalog.notify import send_email
from datetime import datetime as dt, timedelta as td
from loguru import logger
from pathlib import Path
import asyncio
import os
import tomllib

try:
    import uvloop
    HAS_UVLOOP = True
except:
    HAS_UVLOOP = False

async def get_logs_threat(ngfw: NGFW):
    logger.info(f"Gathering Logs (Threat) from {ngfw.name}...")
    return await ngfw.get_logs_threat(delta=td(hours=24))

async def get_logs_events(ngfw: NGFW):
    logger.info(f"Gathering Logs (Events) from {ngfw.name}...")
    return await ngfw.get_logs_events(delta=td(hours=24), insert_only=True)


async def run(config: dict):
    ngfws = [
        NGFW(name=name, host=firewall["host"], port=firewall["port"], api_key=firewall["apikey"],)
        for name, firewall in config["firewalls"].items()
    ]

    now = dt.now()
    values = [
        (now.strftime("logs/logs_threat_%d%b%Y.txt"), "Threat", get_logs_threat),
        (now.strftime("logs/logs_events_%d%b%Y.txt"), "Events", get_logs_events),
    ]

    for file, name, func in values:
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "w+") as fout:
            tasks = asyncio.gather(*map(func, ngfws), return_exceptions=True)
            for ngfw, logs in zip(ngfws, await tasks):
                if isinstance(logs, Exception):
                    logger.error(f"Failed to gather logs ({name}) from {ngfw.name}")
                    print(f"{ngfw.name} - FAILED:\n{logs}", file=fout, flush=True)
                else:
                    logger.success(f"Gathered logs ({name}) from {ngfw.name}")
                    print(f"{ngfw.name} - {name} logs:", file=fout)
                    for log in logs:
                        print(log, file=fout)
                print("\n", file=fout, flush=True)

    filenames = [value[0] for value in values]

    logger.info("Sending email...")
    try:
        await send_email(
            host=config["email"]["host"],
            port=config["email"]["port"],
            username=config["email"]["username"],
            password=config["email"]["password"],
            to=config["email"]["to"],
            subject="Daily Firewall Log Digest",
            body="Deliver of the threat and event logs for the Barracuda Firewalls for the past 24 hours",
            filenames=filenames,
        )
        logger.success("Sent notification email!")
    except Exception as e:
        logger.exception(e)


def main():
    ap = ArgumentParser()
    ap.add_argument("--config", "-c", default="config.toml", help="TOML Configuration File for Barracuda Firewalls")
    args = ap.parse_args()

    if not os.path.isfile(args.config):
        logger.critical("Failed to load configuration file")
        return
    
    with open(args.config, "rb") as fin:
        config = tomllib.load(fin)

    factory = uvloop.new_event_loop if HAS_UVLOOP else asyncio.new_event_loop
    with asyncio.Runner(loop_factory=factory) as runner:
        runner.run(run(config))


if __name__ == "__main__":
    main()
