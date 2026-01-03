import asyncio
import os
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

try:
    import psutil
except ImportError:
    psutil = None


CHECK_URL = "https://checkip.amazonaws.com/"


@dataclass(frozen=True)
class Config:
    bot_token: str
    allowed_chat_ids: List[int]
    check_interval_seconds: int
    interfaces: List[str]
    local_addrs: List[str]


def _split_csv(value: str) -> List[str]:
    items = [x.strip() for x in value.split(",")]
    return [x for x in items if x]


def load_config() -> Config:
    load_dotenv()

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    if not bot_token:
        raise RuntimeError("BOT_TOKEN missing in .env")

    allowed_chat_ids_raw = os.getenv("ALLOWED_CHAT_IDS", "").strip()
    if not allowed_chat_ids_raw:
        raise RuntimeError("ALLOWED_CHAT_IDS missing in .env")

    allowed_chat_ids = [
        int(x.strip()) for x in allowed_chat_ids_raw.split(",") if x.strip()
    ]

    interval = int(os.getenv("CHECK_INTERVAL_SECONDS", "60").strip() or "60")
    if interval < 10:
        interval = 10

    interfaces = _split_csv(os.getenv("INTERFACES", "").strip())
    local_addrs = _split_csv(os.getenv("LOCAL_ADDRS", "").strip())

    return Config(
        bot_token=bot_token,
        allowed_chat_ids=allowed_chat_ids,
        check_interval_seconds=interval,
        interfaces=interfaces,
        local_addrs=local_addrs,
    )

def _resolve_interface_ipv4_addrs(interfaces: List[str]) -> List[str]:
    if not interfaces:
        return []

    if psutil is None:
        raise RuntimeError(
            "INTERFACES is set, but psutil is not installed. Install psutil or use LOCAL_ADDRS instead."
        )

    addrs = []
    all_if_addrs = psutil.net_if_addrs()

    for ifname in interfaces:
        if ifname not in all_if_addrs:
            continue
        for a in all_if_addrs[ifname]:
            if a.family == socket.AF_INET and a.address and a.address != "127.0.0.1":
                addrs.append(a.address)

    seen = set()
    unique = []
    for ip in addrs:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


async def fetch_public_ip(
    session: aiohttp.ClientSession, local_addr: Optional[str]
) -> str:
    timeout = aiohttp.ClientTimeout(total=10)

    connector = None
    if local_addr:
        connector = aiohttp.TCPConnector(local_addr=(local_addr, 0))

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as s:
        async with s.get(CHECK_URL, headers={"User-Agent": "ip-watcher-bot"}) as resp:
            resp.raise_for_status()
            text = (await resp.text()).strip()
            return text


async def fetch_all_public_ips(cfg: Config) -> Dict[str, str]:
    """
    Returns mapping key -> public_ip
    key is either "default" or "src:<local_ip>"
    """
    local_addrs = cfg.local_addrs[:] if cfg.local_addrs else _resolve_interface_ipv4_addrs(cfg.interfaces)

    results: Dict[str, str] = {}

    if not local_addrs:
        async with aiohttp.ClientSession() as session:
            ip = await fetch_public_ip(session, None)
            results["default"] = ip
        return results

    async def one(addr: str) -> Tuple[str, str]:
        async with aiohttp.ClientSession() as session:
            ip = await fetch_public_ip(session, addr)
            return f"src:{addr}", ip

    tasks = [one(addr) for addr in local_addrs]
    for key, ip in await asyncio.gather(*tasks, return_exceptions=False):
        results[key] = ip

    return results


def format_ip_map(ip_map: Dict[str, str]) -> str:
    if not ip_map:
        return "No IP result."

    if list(ip_map.keys()) == ["default"]:
        return f"Public IP: `{ip_map['default']}`"

    lines = ["Public IPs (by source address):"]
    for k in sorted(ip_map.keys()):
        lines.append(f"- {k}: `{ip_map[k]}`")
    return "\n".join(lines)


def in_allowed_chat(update: Update, cfg: Config) -> bool:
    chat = update.effective_chat
    if chat is None:
        return False
    return chat.id in cfg.allowed_chat_ids


async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.application.bot_data["cfg"]

    if not in_allowed_chat(update, cfg):
        return

    try:
        ip_map = await fetch_all_public_ips(cfg)
        await update.message.reply_text(format_ip_map(ip_map), parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"Error fetching IP: {e}")


async def periodic_check(context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.application.bot_data["cfg"]
    last_map: Dict[str, str] = context.application.bot_data.get("last_ip_map", {})

    try:
        new_map = await fetch_all_public_ips(cfg)
    except Exception as e:
        # Avoid spamming errors; keep it quiet unless you want error reporting
        context.application.bot_data["last_error"] = str(e)
        return

    if not last_map:
        context.application.bot_data["last_ip_map"] = new_map
        return

    if new_map != last_map:
        context.application.bot_data["last_ip_map"] = new_map
        text = "Public IP changed:\n" + format_ip_map(new_map)
        for chat_id in cfg.allowed_chat_ids:
            await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode="Markdown",
            )


def main() -> None:
    cfg = load_config()

    app = Application.builder().token(cfg.bot_token).build()
    app.bot_data["cfg"] = cfg
    app.bot_data["last_ip_map"] = {}

    app.add_handler(CommandHandler("ip", cmd_ip))

    app.job_queue.run_repeating(
        periodic_check,
        interval=cfg.check_interval_seconds,
        first=5,
        name="ip_watcher",
    )

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
