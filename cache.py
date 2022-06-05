import pickle
import time
from dnslib import QTYPE, RR, A, AAAA, NS, PTR

qtype_to_int = {1: (QTYPE.A, A),
                2: (QTYPE.NS, NS),
                12: (QTYPE.PTR, PTR),
                28: (QTYPE.AAAA, AAAA)}


class Cache:
    TIME_CLEANED = time.time()

    def __init__(self):
        self.cache = {}
        for record_type in qtype_to_int.keys():
            self.cache[record_type] = {}

    def get_on_exist(self, parsed):
        record_name = str(parsed.q.qname)
        q_type = parsed.q.qtype
        if q_type not in self.cache or record_name not in self.cache[q_type]:
            return
        reply = parsed.reply()
        reply.add_answer(self.get_pr_record(q_type, record_name))
        return reply.pack()

    def get_pr_record(self, q_type, body):
        return RR(body, qtype_to_int[q_type][0], rdata=qtype_to_int[q_type][1](self.cache[q_type][body][0]), ttl=60)

    def add_records(self, records):
        for record in records:
            self.cache[record.rtype][str(record.rname)] = (str(record.rdata), time.time(), record.ttl)

    def remove_expired_records(self):
        for q_type in self.cache:
            for q_name in self.cache[q_type]:
                time_record_created = self.cache[q_type][q_name][1]
                ttl = self.cache[q_type][q_name][2]
                if time.time() - time_record_created > ttl:
                    del self.cache[q_type][q_name]
        self.TIME_CLEANED = time.time()

    def save_cache(self, cache_file_name):
        with open(cache_file_name, 'wb+') as dump:
            pickle.dump(self, dump)

    @staticmethod
    def load_cache(cache_file_name):
        try:
            with open(cache_file_name, 'rb') as dump:
                cache = pickle.load(dump)
            print('Cache loaded')
            return cache
        except FileNotFoundError:
            print('Cache does not exist')
            return Cache()
