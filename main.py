from cache import Cache
import time
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from dnslib import DNSRecord, QTYPE, A, AAAA, NS, PTR

qtype_to_int = {1: (QTYPE.A, A),
                2: (QTYPE.NS, NS),
                12: (QTYPE.PTR, PTR),
                28: (QTYPE.AAAA, AAAA)}
ROOT_SERVER = "8.8.8.8",  # Google Public DNS
CACHE_FILE = "cache.txt"


class Server:
    def __init__(self, cache, host_ip="localhost", port=53):
        self.server = socket(AF_INET, SOCK_DGRAM)
        self.server.settimeout(2)
        self.server.bind((host_ip, port))
        self.cache = cache

    def on_start(self):
        while True:
            data, address = self.get_packet()
            response = self.packege_process(data)
            self.clear_cache_if_need(time.time())
            self.server.sendto(response, address)

    def clear_cache_if_need(self, time_now):
        if time_now - self.cache.TIME_CLEANED > 30:
            self.cache.remove_expired_records()

    def get_packet(self):
        try:
            return self.server.recvfrom(256)
        except timeout:
            return self.get_packet()
        except Exception as e:
            self.server.close()
            print(e)
            exit()

    def packege_process(self, package: bytes) -> bytes:
        ip = ROOT_SERVER
        answer_in_byte = None
        answer = None
        while answer is None or len(answer.rr) == 0:
            parsed_packet = DNSRecord.parse(package)
            recorder_of_cache = self.cache.get_on_exist(parsed_packet)
            if recorder_of_cache:
                return recorder_of_cache
            try:
                answer_in_byte = parsed_packet.send(ip, timeout=4)
            except timeout:
                ip = ROOT_SERVER
                continue
            answer = DNSRecord.parse(answer_in_byte)
            if answer.header.rcode == 3:
                return answer_in_byte
            self.cache.add_records(answer.ar)
            ip = next((str(x.rdata) for x in answer.ar if x.rtype == 1), -1)
            if ip == -1 and len(answer.rr) == 0:
                resp = self.packege_process(DNSRecord.question(str(answer.auth[0].rdata)).pack())
                ip = str(DNSRecord.parse(resp).rr[0].rdata)
        self.cache.add_records(answer.rr)
        return answer_in_byte


def main():
    cache = Cache.load_cache(CACHE_FILE)
    try:
        print('')
        Server(cache).on_start()
    except (KeyboardInterrupt, SystemExit):
        print('Exit. Cache saved.')
        cache.save_cache(CACHE_FILE)


if __name__ == '__main__':
    main()
