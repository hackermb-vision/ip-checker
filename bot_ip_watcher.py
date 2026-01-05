import asyncio
import logging
import os
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

try:
    import psutil
except ImportError:
    psutil = None


CHECK_URL = "https://checkip.amazonaws.com/"

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)


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

    logger.info("Loading configuration from environment...")

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    if not bot_token:
        logger.error("BOT_TOKEN missing in .env file")
        raise RuntimeError("BOT_TOKEN missing in .env")

    allowed_chat_ids_raw = os.getenv("ALLOWED_CHAT_IDS", "").strip()
    if not allowed_chat_ids_raw:
        logger.error("ALLOWED_CHAT_IDS missing in .env file")
        raise RuntimeError("ALLOWED_CHAT_IDS missing in .env")

    try:
        allowed_chat_ids = [
            int(x.strip()) for x in allowed_chat_ids_raw.split(",") if x.strip()
        ]
        logger.info(f"Loaded {len(allowed_chat_ids)} allowed chat ID(s)")
    except ValueError as e:
        logger.error(f"Invalid ALLOWED_CHAT_IDS format: {e}")
        raise RuntimeError(f"ALLOWED_CHAT_IDS must be comma-separated integers: {e}")

    interval = int(os.getenv("CHECK_INTERVAL_SECONDS", "60").strip() or "60")
    if interval < 10:
        logger.warning(f"CHECK_INTERVAL_SECONDS too low ({interval}), setting to minimum 10")
        interval = 10
    logger.info(f"Check interval set to {interval} seconds")

    interfaces = _split_csv(os.getenv("INTERFACES", "").strip())
    local_addrs = _split_csv(os.getenv("LOCAL_ADDRS", "").strip())

    if interfaces:
        logger.info(f"Monitoring interfaces: {', '.join(interfaces)}")
    if local_addrs:
        logger.info(f"Monitoring local addresses: {', '.join(local_addrs)}")

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
        logger.error("INTERFACES is set, but psutil is not installed")
        raise RuntimeError(
            "INTERFACES is set, but psutil is not installed. Install psutil or use LOCAL_ADDRS instead."
        )

    addrs = []
    all_if_addrs = psutil.net_if_addrs()

    for ifname in interfaces:
        if ifname not in all_if_addrs:
            logger.warning(f"Interface {ifname} not found, skipping")
            continue
        for a in all_if_addrs[ifname]:
            if a.family == socket.AF_INET and a.address and a.address != "127.0.0.1":
                addrs.append(a.address)
                logger.debug(f"Found IPv4 address {a.address} on interface {ifname}")

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

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as s:
            async with s.get(CHECK_URL, headers={"User-Agent": "ip-watcher-bot"}) as resp:
                resp.raise_for_status()
                text = (await resp.text()).strip()
                logger.debug(f"Fetched IP: {text}" + (f" (via {local_addr})" if local_addr else ""))
                return text
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching public IP" + (f" via {local_addr}" if local_addr else "") + f": {e}")
        raise
    except asyncio.TimeoutError as e:
        logger.error(f"Timeout fetching public IP" + (f" via {local_addr}" if local_addr else ""))
        raise


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
        logger.warning(f"Unauthorized /ip command from chat_id={update.effective_chat.id}")
        await update.message.reply_text(
            "❌ Sorry, you are not authorized to use this bot.\n\n"
            "This bot is restricted to specific users only."
        )
        return

    logger.info(f"Processing /ip command from chat_id={update.effective_chat.id}")

    try:
        ip_map = await fetch_all_public_ips(cfg)
        await update.message.reply_text(format_ip_map(ip_map), parse_mode="Markdown")
        logger.info(f"Successfully sent IP information to chat_id={update.effective_chat.id}")
    except Exception as e:
        logger.error(f"Error fetching IP for chat_id={update.effective_chat.id}: {e}", exc_info=True)
        await update.message.reply_text(
            f"❌ Error fetching IP address:\n\n`{str(e)}`\n\n"
            f"Please check the bot logs for more details.",
            parse_mode="Markdown"
        )


async def periodic_check(context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.application.bot_data["cfg"]
    last_map: Dict[str, str] = context.application.bot_data.get("last_ip_map", {})

    try:
        new_map = await fetch_all_public_ips(cfg)
        # Clear any previous error
        if "last_error" in context.application.bot_data:
            del context.application.bot_data["last_error"]
    except Exception as e:
        error_msg = str(e)
        context.application.bot_data["last_error"] = error_msg
        logger.error(f"Periodic check failed: {error_msg}", exc_info=True)
        return

    if not last_map:
        context.application.bot_data["last_ip_map"] = new_map
        logger.info(f"Initial IP check completed: {format_ip_map(new_map)}")
        return

    if new_map != last_map:
        context.application.bot_data["last_ip_map"] = new_map
        logger.info(f"IP change detected! Old: {last_map}, New: {new_map}")
        text = "🔄 Public IP changed:\n" + format_ip_map(new_map)
        for chat_id in cfg.allowed_chat_ids:
            try:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode="Markdown",
                )
                logger.info(f"Notified chat_id={chat_id} about IP change")
            except Exception as e:
                logger.error(f"Failed to notify chat_id={chat_id}: {e}")


async def handle_unauthorized_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle messages from unauthorized users."""
    cfg: Config = context.application.bot_data["cfg"]
    
    if not in_allowed_chat(update, cfg):
        chat_id = update.effective_chat.id if update.effective_chat else "unknown"
        logger.warning(f"Unauthorized message from chat_id={chat_id}")
        try:
            await update.message.reply_text(
                "❌ Sorry, you are not authorized to use this bot.\n\n"
                "This bot is restricted to specific users only."
            )
        except Exception as e:
            logger.error(f"Failed to send unauthorized message response to chat_id={chat_id}: {e}")


def main() -> None:
    try:
        cfg = load_config()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}", exc_info=True)
        raise

    logger.info("Building Telegram bot application...")
    app = Application.builder().token(cfg.bot_token).build()
    app.bot_data["cfg"] = cfg
    app.bot_data["last_ip_map"] = {}

    logger.info("Registering command handlers...")
    app.add_handler(CommandHandler("ip", cmd_ip))
    
    # Add a handler for all other messages from unauthorized users
    app.add_handler(MessageHandler(filters.ALL, handle_unauthorized_message))

    logger.info(f"Starting periodic IP check (interval: {cfg.check_interval_seconds}s)...")
    app.job_queue.run_repeating(
        periodic_check,
        interval=cfg.check_interval_seconds,
        first=5,
        name="ip_watcher",
    )

    logger.info("Starting bot polling...")
    logger.info("Bot is now running. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
