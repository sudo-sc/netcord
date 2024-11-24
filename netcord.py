import discord
import subprocess
import yaml
import logging
import re
import httpx
import asyncio
import dns.message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

def get_config(filename="config.yaml"):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

cfg = get_config()

if client_id := cfg["client_id"]:
    logging.info(f"\n\nUse this link to invite the bot to your server:\nhttps://discord.com/api/oauth2/authorize?client_id={client_id}&permissions=2147559424&integration_type=0&scope=applications.commands+bot\n")

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

async def schedule_deletion(message):
    """Schedule the deletion of a message after a specified time."""
    delete_time = cfg.get('message_deletion_time', 30)
    if delete_time > 0:
        logging.info(f"Scheduling deletion for response in channel {message.channel.id} in {delete_time} seconds")
        await asyncio.sleep(delete_time)
        try:
            await message.delete()
            logging.info(f"Deleted response message from channel {message.channel.id}")
        except discord.NotFound:
            logging.info("Message was already deleted.")

async def run_command(ctx, command, description):
    await ctx.defer()  # Acknowledge the command to prevent timeout
    logging.info(f"User {ctx.author} requested to {description} in channel {ctx.channel.id}")

    if ctx.channel.id not in cfg['allowed_channel_ids']:
        response_message = await ctx.respond("This command cannot be used in this channel.", ephemeral=True)
        await schedule_deletion(response_message)
        return

    try:
        # Execute the command and capture the output
        output = subprocess.run(command, capture_output=True, text=True, check=True)
        logging.info(f"Command output: {output.stdout}")
        response_message = await ctx.send_followup(f'{description.capitalize()} result:\n```{output.stdout}```')
        await schedule_deletion(response_message)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e.stderr}")
        response_message = await ctx.send_followup(f'Command failed with error: {e.stderr}')
        await schedule_deletion(response_message)
    except Exception as e:
        logging.error(f"Error executing {description}: {e}")
        response_message = await ctx.send_followup(f'An error occurred: {e}')
        await schedule_deletion(response_message)

async def dig_record(ctx, domain, record_type):
    await ctx.defer()  # Acknowledge the command to prevent timeout
    if not is_valid_fqdn(domain):
        response_message = await ctx.send_followup("Invalid domain. Please provide a valid fully qualified domain name (FQDN).")
        await schedule_deletion(response_message)
        return

    url = cfg['doh_server']

    try:
        # Construct the DNS query
        query = dns.message.make_query(domain, record_type)
        query_data = query.to_wire()

        async with httpx.AsyncClient() as client:
            # Make a POST request to the DoH server
            response = await client.post(url, headers={"Content-Type": "application/dns-message"}, content=query_data)
            response.raise_for_status()

            # Parse the DNS response
            response_message = dns.message.from_wire(response.content)
            answers = response_message.answer

            if answers:
                result = "\n".join(answer.to_text() for answer in answers)
                response_message = await ctx.send_followup(f'DNS {record_type} records for {domain}:\n```{result}```')
            else:
                response_message = await ctx.send_followup(f'No {record_type} records found for {domain}.')
            await schedule_deletion(response_message)
    except httpx.HTTPStatusError as e:
        logging.error(f"HTTP error occurred: {e}")
        response_message = await ctx.send_followup(f'HTTP error occurred: {e}')
        await schedule_deletion(response_message)
    except Exception as e:
        logging.error(f"Error fetching DNS records for {domain}: {e}")
        response_message = await ctx.send_followup(f'An error occurred while fetching DNS records: {e}')
        await schedule_deletion(response_message)

@bot.slash_command(name=cfg['commands']['ping']['name'], description=cfg['commands']['ping']['description'])
async def ping(ctx, target: str):
    if not is_valid_dualstack_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv4, IPv6 address, or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), target], f'ping {target}')

@bot.slash_command(name=cfg['commands']['ping4']['name'], description=cfg['commands']['ping4']['description'])
async def ping4(ctx, target: str):
    if not is_valid_v4_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv4 address or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), '-4', target], f'ping IPv4 {target}')

@bot.slash_command(name=cfg['commands']['ping6']['name'], description=cfg['commands']['ping6']['description'])
async def ping6(ctx, target: str):
    if not is_valid_v6_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv6 address or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['ping', '-c', str(cfg['ping_count']), '-6', target], f'ping IPv6 {target}')

@bot.slash_command(name=cfg['commands']['traceroute']['name'], description=cfg['commands']['traceroute']['description'])
async def traceroute(ctx, target: str):
    if not is_valid_dualstack_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv4, IPv6 address, or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['traceroute', target], f'traceroute {target}')

@bot.slash_command(name=cfg['commands']['traceroute4']['name'], description=cfg['commands']['traceroute4']['description'])
async def traceroute4(ctx, target: str):
    if not is_valid_v4_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv4 address or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['traceroute', '-4', target], f'traceroute IPv4 {target}')

@bot.slash_command(name=cfg['commands']['traceroute6']['name'], description=cfg['commands']['traceroute6']['description'])
async def traceroute6(ctx, target: str):
    if not is_valid_v6_input(target):
        response_message = await ctx.send_followup("Invalid input. Please provide a valid IPv6 address or FQDN.")
        await schedule_deletion(response_message)
        return
    await run_command(ctx, ['traceroute', '-6', target], f'traceroute IPv6 {target}')

@bot.slash_command(name=cfg['commands']['dig_a']['name'], description=cfg['commands']['dig_a']['description'])
async def dig_a(ctx, domain: str):
    await dig_record(ctx, domain, 'A')

@bot.slash_command(name=cfg['commands']['dig_aaaa']['name'], description=cfg['commands']['dig_aaaa']['description'])
async def dig_aaaa(ctx, domain: str):
    await dig_record(ctx, domain, 'AAAA')

bot.run(cfg["bot_token"])