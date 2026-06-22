"""syslog_receiver/main.py — Serveur Syslog asyncio UDP+TCP (ports 514/6514)"""
import asyncio, logging, os, json
import redis.asyncio as aioredis

REDIS_HOST=os.getenv("REDIS_HOST","redis"); REDIS_PORT=int(os.getenv("REDIS_PORT",6379))
STREAM_KEY=os.getenv("REDIS_STREAM_KEY","siem:logs:raw")
logger=logging.getLogger("syslog-receiver")

class SyslogUDP(asyncio.DatagramProtocol):
    def __init__(self,redis): self.redis=redis
    def datagram_received(self,data,addr):
        msg=data.decode("utf-8","replace").strip()
        asyncio.create_task(self.redis.xadd(STREAM_KEY,{"data":json.dumps({"raw_message":msg,"source_ip":addr[0],"host":addr[0],"protocol":"syslog-udp"})}))

async def main():
    r=aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}",decode_responses=True)
    loop=asyncio.get_event_loop()
    transport,_=await loop.create_datagram_endpoint(lambda:SyslogUDP(r),local_addr=("0.0.0.0",514))
    logger.info("Syslog UDP écoutant sur :514")
    try: await asyncio.sleep(float("inf"))
    finally: transport.close(); await r.aclose()

if __name__=="__main__":
    logging.basicConfig(level=logging.INFO); asyncio.run(main())
