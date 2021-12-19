#!/usr/bin/env python3

########################
#
# Config items
#
########################
import certifi
from aiohttp import ServerFingerprintMismatch
from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS, SYNCHRONOUS

from aioedgeos import *
import asyncio
from contextlib import AsyncExitStack
import logging
import os
import warnings
import aiohttp
from binascii import a2b_hex, b2a_hex

load_dotenv("settings.env")

DEBUG_MODE = os.environ.get('DEBUG_MODE', None)

'''
If you want to replace the system hostname with something
else and don't want to change the router config you can
change it here
'''
ROUTER_TAGNAME = os.environ.get('ROUTER_TAGNAME', None)

''' Credentials to get into the webUI '''
ROUTER_USERNAME = os.environ['ROUTER_USERNAME']
ROUTER_PASSWORD = os.environ['ROUTER_PASSWORD']
ROUTER_URL = os.environ['ROUTER_URL']

''' 
TRUE for SSL that will validate or the base64 sha256
fingerprint for the host
'''
ROUTER_SSL = os.environ.get('ROUTER_SSL', 'f' * 64).lower()  # Default to enforcing ssl

''' InfluxDB settings '''
INFLUX_URL = os.environ['INFLUX_URL']
INFLUX_TOKEN = os.environ['INFLUX_TOKEN']
INFLUX_ORG = os.environ.get('INFLUX_ORG')
INFLUX_BUCKET = os.environ.get('INFLUX_BUCKET')

''' 
Latency settings - optional, by default will 
ping 1.1.1.1 every 120 seconds with 3 pings and record
the stats.

PING_TARGET can take multiple hosts like 1.1.1.1/8.8.8.8
and will interleve checks
'''
PING_TARGET = os.environ.get('PING_TARGET', '1.1.1.1')
PING_COUNT = int(os.environ.get('PING_COUNT', 3))
PING_SIZE = int(os.environ.get('PING_SIZE', 50))
PING_INTERVAL = int(os.environ.get('PING_INTERVAL', 120))

warnings.simplefilter("ignore")

ssl_check = True
if isinstance(ROUTER_SSL, str) and len(ROUTER_SSL) == 64:
    # presume this is a fingerprint
    ssl_check = aiohttp.Fingerprint(a2b_hex(ROUTER_SSL))
elif ROUTER_SSL in ['no', 'false']:
    ssl_check = False
elif ROUTER_SSL in ['yes', 'true']:
    ssl_check = True
else:
    raise Exception(f"ROUTER_SSL {ROUTER_SSL} is invalid")

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger()
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


class SystemStats:
    def __new__(cls, router, cpu, mem, uptime):
        return Point("SystemStats").tag("router", router).field("cpu", int(cpu)).field("mem", int(mem)).field("uptime", int(uptime))


class Interfaces:
    def __new__(cls, router, ifname, rx_packets, rx_bytes, rx_errors, rx_dropped, tx_packets, tx_bytes, tx_errors,
                tx_dropped):
        return Point("Interfaces")\
            .tag("router", router)\
            .tag("ifname", ifname)\
            .field("rx_packets", int(rx_packets))\
            .field("rx_bytes", int(rx_bytes))\
            .field("rx_errors", int(rx_errors))\
            .field("rx_dropped", int(rx_dropped))\
            .field("tx_packets", int(tx_packets))\
            .field("tx_bytes", int(tx_bytes))\
            .field("tx_errors", int(tx_errors))\
            .field("tx_dropped", int(tx_dropped))


if_fields = [
    'rx_packets', 'rx_bytes', 'rx_errors', 'rx_dropped',
    'tx_packets', 'tx_bytes', 'tx_errors', 'tx_dropped',
]


def process_interfaces(value, hostname):
    for interface, x in value.items():
        datapoint = Interfaces(router=hostname,
                               ifname=interface,
                               **dict((field_name, int(x['stats'][field_name])) for field_name in if_fields)
                               )
        yield datapoint


# @lineprotocol
# class Clients(NamedTuple):
#     router: TAG
#     num_active: INT


# @lineprotocol
# class DPI(NamedTuple):
#     router: TAG
#     client_id: TAG
#     client_name: TAG
#     dpi: TAG
#     dpi_category: TAG
#     rx_bytes: INT
#     tx_bytes: INT


ip2mac1 = {}
ip2mac2 = {}


def config_extract_map(config):
    ip2mac = {}
    for mapping in find_subkey(config, 'static-mapping'):
        for name, value in mapping.items():
            ip2mac[value['ip-address']] = {
                'ip': value['ip-address'],
                'mac': value['mac-address'],
                'name': name,
            }
    global ip2mac1
    ip2mac1.update(ip2mac)
    return ip2mac


def leases_extract(leases):
    ip2mac = {}
    try:
        for lan, lan_lease in leases['dhcp-server-leases'].items():
            if not isinstance(lan_lease, dict):
                continue
            for ip, value in lan_lease.items():
                name = value['client-hostname']
                if len(name) == 0:
                    name = "-"
                ip2mac[ip] = {
                    'ip': ip,
                    'mac': value['mac'],
                    'name': name
                }
    except:
        pass
    global ip2mac2
    ip2mac2.update(ip2mac)
    return ip2mac


def best_id_name(ip):
    if ip in ip2mac1:
        return ip2mac1[ip]['mac'], ip2mac1[ip]['name']
    if ip in ip2mac2:
        return ip2mac2[ip]['mac'], ip2mac2[ip]['name']
    return ip, "UNK"


def process_export(value, hostname):
    datapoint = Clients(router=hostname, num_active=len(value))
    yield datapoint
    if not isinstance(value, dict):
        return
    for ip, dpi in value.items():
        oid, name = best_id_name(ip)
        for app, value in dpi.items():
            app, cat = app.split('|', 1)
            rx_bytes = int(value['rx_bytes'])
            tx_bytes = int(value['tx_bytes'])
            rx_rate = int(value['rx_rate'])
            tx_rate = int(value['tx_rate'])
            if rx_rate == 0 and tx_rate == 0:
                continue
            yield DPI(router=hostname, client_id=oid,
                      client_name=name, dpi=app,
                      dpi_category=cat,
                      rx_bytes=rx_bytes,
                      tx_bytes=tx_bytes)
    return


# @lineprotocol
# class Users(NamedTuple):
#     router: TAG
#     user_type: TAG
#     count: INT


def process_users(value, hostname):
    for user_type, value in value.items():
        yield Users(router=hostname, user_type=user_type, count=len(value))


async def dhcp_refresh(router):
    await router.dhcp_leases()
    leases_extract(router.sysdata['dhcp_leases'])


class LatencyPoint:
    def __new__(cls, router, target, latency, lost):
        return Point("Latency") \
            .tag("router", router) \
            .tag("target", target) \
            .field("latency", float(latency)) \
            .field("lost", int(lost))


async def latency_check(local_client, edgeos, hostname, target, count, size):
    try:
        logging.info(f"Pinging {target}")
        await edgeos.ping(target=target, count=count, size=size)
        local_client.write(INFLUX_BUCKET,
                           INFLUX_ORG,
                           LatencyPoint(router=hostname,
                                        target=target,
                                        latency=edgeos.sysdata['ping-data'][target].get('avg', '1000'),
                                        lost=edgeos.sysdata['ping-data'][target].get('lost', None)))
        logging.info(f"Pinging {target} and storing data done, sleeping for {PING_INTERVAL} seconds")
    except:
        logging.exception("latency_check")


async def main_loop():
    async with AsyncExitStack() as stack:
        try:
            ''' ROUTER SETUP '''
            logging.info(f"CONNECTING TO ROUTER {ROUTER_URL} with user {ROUTER_USERNAME}")
            router = await stack.enter_async_context(
                EdgeOS(ROUTER_USERNAME, ROUTER_PASSWORD, ROUTER_URL, ssl=ssl_check))
            await router.config()
            config_extract_map(router.sysconfig)

            hostname = ROUTER_TAGNAME or router.sysconfig['system']['host-name']

            ''' Sanity check host '''
            try:
                if router.sysconfig['system']['traffic-analysis']['dpi'] == 'enable' and \
                        router.sysconfig['system']['traffic-analysis']['export'] == 'enable':
                    logging.debug(f"{hostname} appears to have DPI enabled")
                else:
                    raise
            except:
                logging.warning(f"{hostname} DOES NOT APPEAR TO HAVE DPI ENABLED, FUNCTIONALITY WILL BE LIMITED")

            logging.info(f"CONNECTED TO ROUTER {hostname}")

            logging.info("LAUNCHING DHCP SCRAPER")
            await stack.enter_async_context(TaskEvery(dhcp_refresh, router, interval=600))

            ''' INFLUX SETUP '''
            logging.info(f"CONFIGURING INFLUX")
            with InfluxDBClient(url=INFLUX_URL,
                                token=INFLUX_TOKEN,
                                org=INFLUX_ORG,
                                ssl_ca_cert=certifi.where()) as local_client:
                write_api = local_client.write_api(write_options=SYNCHRONOUS)
                logging.info(f"CONFIGURED INFLUX")
                '''
                For ping testing, let's breakdown the list into targets and make sure that
                we don't start pinging all of them at once by staggering them based on their
                position in the list
                '''
                targets = PING_TARGET.split('/')
                for i, target in enumerate(targets):
                    offset = i * int(PING_INTERVAL / len(targets))
                    logging.info(f"LAUNCHING LATENCY CHECK LOOP FOR {target} with offset {offset}")
                    await stack.enter_async_context(TaskEvery(latency_check,
                                                              write_api,
                                                              router,
                                                              hostname,
                                                              target,
                                                              PING_COUNT,
                                                              PING_SIZE,
                                                              interval=PING_INTERVAL,
                                                              offset=offset))

                logging.info("STARTING MAIN WEBSOCKET LOOP")
                async for payload in router.stats(subs=["export", "interfaces", "system-stats", "config-change", "users"]):
                    for key, value in payload.items():
                        if not isinstance(value, dict):
                            logging.warning(
                                f"{value} for {key} isn't a dict, would likely cause trouble in processing skipping")
                            continue
                        if key == 'system-stats':
                            datapoint = SystemStats(router=hostname,
                                                    cpu=value['cpu'],
                                                    mem=value['mem'],
                                                    uptime=value['uptime'])
                            write_api.write(INFLUX_BUCKET, INFLUX_ORG, datapoint)
                        elif key == 'interfaces':
                            write_api.write(INFLUX_BUCKET, INFLUX_ORG, process_interfaces(value, hostname))
                        # elif key == 'export':
                        #     await write_api.write(process_export(value, hostname))
                        # elif key == 'users':
                        #     await write_api.write(process_users(value, hostname))
                        # elif key == 'config-change' and value['commit'] == 'ended':
                        #     # ip2mac1 = config_extract_map(router.sysconfig)
                        #     hostname = ROUTER_TAGNAME or router.sysconfig['system']['host-name']
                        # else:
                        #     logging.debug(f"got datapoint {key} but I don't know how to handle it, ignoring")
        except ServerFingerprintMismatch as e:
            fphash = b2a_hex(e.got).decode()
            print(f'''
===============   TLS/SSL HASH MISMATCH ===============
Server replied with different fingerprint hash of {fphash}, it's likely you didn't setup the 
ssl for your router.  If this is the case please update your environment with the following.

ROUTER_SSL={fphash}
===============   TLS/SSL HASH MISMATCH ===============''')


if __name__ == '__main__':
    rh = ROUTER_TAGNAME or "**get hostname from system config**"

    print(f'''
    ================================================
    ROUTER_TAGNAME  = {rh}
    ROUTER_USERNAME = {ROUTER_USERNAME}
    ROUTER_PASSWORD = **HIDDEN**
    ROUTER_URL      = {ROUTER_URL}
    ROUTER_SSL      = {ROUTER_SSL}
     - ssl_check    -> {ssl_check!r}
    INFLUX_URL      = {INFLUX_URL}
    INFLUX_ORG      = {INFLUX_ORG}
    INFLUX_BUCKET   = {INFLUX_BUCKET}
    PING_TARGET     = {PING_TARGET}
    PING_COUNT      = {PING_COUNT}
    PING_SIZE       = {PING_SIZE}
    PING_INTERVAL   = {PING_INTERVAL}
    ================================================
    ''')

    loop = asyncio.get_event_loop()
    loop.create_task(main_loop())
    loop.run_forever()
