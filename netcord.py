import discord
import subprocess
import yaml
import logging
import re
import httpx
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

def get_config(filename="config.yaml"):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

cfg = get_config()

intents = discord.Intents.default()

bot = discord.Bot(intents=intents)

# Regular expressions for validation
ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
ipv6_pattern = re.compile(r'^[0-9a-fA-F:]+$')
fqdn_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}$')

def is_valid_ipv4(address):
    return ipv4_pattern.match(address) is not None and all(0 <= int(octet) <= 255 for octet in address.split('.'))

def is_valid_ipv6(address):
    return ipv6_pattern.match(address) is not None

def is_valid_fqdn(domain):
    return fqdn_pattern.match(domain) is not None

def is_valid_v4_input(input):
    return is_valid_ipv4(input) or is_valid_fqdn(input)

def is_valid_v6_input(input):
    return is_valid_ipv6(input) or is_valid_fqdn(input)

def is_valid_dualstack_input(input):
    return is_valid_ipv4(input) or is_valid_ipv6(input) or is_valid_fqdn(input)

async def schedule_deletion(response, channel_id):
    """Schedule the deletion of a message after a specified time."""
    delete_time = cfg.get('message_deletion_time', 30)
    if delete_time > 0:
        logging.info(f"Scheduling deletion for response in channel {channel_id} in {delete_time} seconds")
        await asyncio.sleep(delete_time)
        try:
            await response.delete()
            logging.info(f"Deleted response message from channel {channel_id}")
        except discord.NotFound:
            logging.info("Message was already deleted.")

async def run_command(ctx, command, description):
    await ctx.defer()  # Acknowledge the command to prevent timeout
    logging.info(f"User {ctx.author} requested to {description} in channel {ctx.channel.id}")

    if ctx.channel.id not in cfg['allowed_channel_ids']:
        await ctx.respond("This command cannot be used in this channel.", ephemeral=True)
        return

    try:
        # Execute the command and capture the output
        output = subprocess.run(command, capture_output=True, text=True, check=True)
        logging.info(f"Command output: {output.stdout}")
        response = await ctx.respond(f'{description.capitalize()} result:\n```{output.stdout}```', ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e.stderr}")
        response = await ctx.respond(f'Command failed with error: {e.stderr}', ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
    except Exception as e:
        logging.error(f"Error executing {description}: {e}")
        response = await ctx.respond(f'An error occurred: {e}', ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)

async def dig_record(ctx, domain, record_type):
    if not is_valid_fqdn(domain):
        response = await ctx.respond("Invalid domain. Please provide a valid fully qualified domain name (FQDN).", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return

    url = cfg['doh_server']
    headers = {"accept": "application/dns-json"}
    params = {"name": domain, "type": record_type}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            answers = data.get("Answer", [])
            if answers:
                result = "\n".join(f"{answer['name']} {answer['type']} {answer['data']}" for answer in answers)
                response = await ctx.respond(f'DNS {record_type} records for {domain}:\n```{result}```', ephemeral=False)
            else:
                response = await ctx.respond(f'No {record_type} records found for {domain}.', ephemeral=False)
            await schedule_deletion(response, ctx.channel.id)
    except Exception as e:
        logging.error(f"Error fetching DNS records for {domain}: {e}")
        response = await ctx.respond(f'An error occurred while fetching DNS records: {e}', ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)

@bot.slash_command(name=cfg['commands']['ping']['name'], description=cfg['commands']['ping']['description'])
async def ping(ctx, target: str):
    if not is_valid_dualstack_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv4, IPv6 address, or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), target], f'ping {target}')

@bot.slash_command(name=cfg['commands']['ping4']['name'], description=cfg['commands']['ping4']['description'])
async def ping4(ctx, target: str):
    if not is_valid_v4_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv4 address or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), '-4', target], f'ping IPv4 {target}')

@bot.slash_command(name=cfg['commands']['ping6']['name'], description=cfg['commands']['ping6']['description'])
async def ping6(ctx, target: str):
    if not is_valid_v6_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv6 address or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), '-6', target], f'ping IPv6 {target}')

@bot.slash_command(name=cfg['commands']['traceroute']['name'], description=cfg['commands']['traceroute']['description'])
async def traceroute(ctx, target: str):
    if not is_valid_dualstack_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv4, IPv6 address, or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['traceroute', target], f'traceroute {target}')

@bot.slash_command(name=cfg['commands']['traceroute4']['name'], description=cfg['commands']['traceroute4']['description'])
async def traceroute4(ctx, target: str):
    if not is_valid_v4_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv4 address or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['traceroute', '-4', target], f'traceroute IPv4 {target}')

@bot.slash_command(name=cfg['commands']['traceroute6']['name'], description=cfg['commands']['traceroute6']['description'])
async def traceroute6(ctx, target: str):
    if not is_valid_v6_input(target):
        response = await ctx.respond("Invalid input. Please provide a valid IPv6 address or FQDN.", ephemeral=False)
        await schedule_deletion(response, ctx.channel.id)
        return
    await run_command(ctx, ['traceroute', '-6', target], f'traceroute IPv6 {target}')

@bot.slash_command(name=cfg['commands']['dig_a']['name'], description=cfg['commands']['dig_a']['description'])
async def dig_a(ctx, domain: str):
    await dig_record(ctx, domain, 'A')

@bot.slash_command(name=cfg['commands']['dig_aaaa']['name'], description=cfg['commands']['dig_aaaa']['description'])
async def dig_aaaa(ctx, domain: str):
    await dig_record(ctx, domain, 'AAAA')

bot.run(cfg["bot_token"])
