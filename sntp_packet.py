import datetime
import struct

class SNTP_Packet:
    def __init__(self):
        self.li = 0
        self.vn = 0
        self.mode = 0
        self.stratum = 0
        self.poll = 0
        self.precision = 0
        self.root_delay = 0
        self.root_dispersion = 0
        self.reference_identifier = 0
        self.reference_timestamp = (0, 0)
        self.originate_timestamp = (0, 0)
        self.receive_timestamp = (0, 0)
        self.transmit_timestamp = (0, 0)

        self.li_vn_mode_format = 'B'
        self.stratum_format = 'B'
        self.poll_format = 'B'
        self.precision_format = 'B'
        self.root_delay_format = 'I'
        self.root_dispersion_format = 'I'
        self.reference_identifier_format = 'I'
        self.reference_timestamp_format = 'II'
        self.originate_timestamp_format = 'II'
        self.receive_timestamp_format = 'II'
        self.transmit_timestamp_format = 'II'

    def to_bytes(self):        
        return struct.pack(self.get_packet_format(), *self.get_packet_value())

    def from_bytes(self, buff):
        fields = struct.unpack(self.get_packet_format(), buff)
        li, vn, mode = self.decode_li_vn_mode(fields[0])
        self.li = li
        self.vn = vn
        self.mode = mode

        self.stratum = fields[1]
        self.poll = fields[2]
        self.precision = fields[3]
        self.root_delay = fields[4]
        self.root_dispersion = fields[5]
        self.reference_identifier = fields[6]
        self.reference_timestamp = (fields[7], fields[8])
        self.originate_timestamp = (fields[9], fields[10])
        self.receive_timestamp = (fields[11], fields[12])
        self.transmit_timestamp = (fields[13], fields[14])

        return self
    
    # leap indicator, version number and mode are combined into a single byte
    # create two functions to encode/decode it.
    def encode_li_vn_mode(self):
        return (self.li << 6) + (self.vn << 3) + self.mode

    def decode_li_vn_mode(self, val):
        li_mask = 0b11000000
        vn_mask = 0b00111000
        mode_mask = 0b00000111

        li = (val & li_mask) >> 6
        vn = (val & vn_mask) >> 3
        mode = val & mode_mask
        return (li, vn, mode)

    def encode_ntp_timestamp(self, timestamp):
        ntp_timestamp = timestamp - self.get_ntp_timestamp_offset()
        second = int(ntp_timestamp)
        
        # convert the fractional second to an integer
        fraction_second = int((ntp_timestamp - second) * (2 ** 32))
        return (second, fraction_second)

    def decode_ntp_timestamp(self, seconds, fraction_seconds):
        fraction_seconds /= 2 ** 32
        ntp_timestamp = seconds + fraction_seconds
        timestamp = ntp_timestamp + self.get_ntp_timestamp_offset()
        return timestamp

    def get_packet_format(self):
        return ''.join([
            '>',
            self.li_vn_mode_format,
            self.stratum_format,
            self.poll_format,
            self.precision_format,
            self.root_delay_format,
            self.root_dispersion_format,
            self.reference_identifier_format,
            self.reference_timestamp_format,
            self.originate_timestamp_format,
            self.receive_timestamp_format,
            self.transmit_timestamp_format
        ])
    
    def get_packet_value(self):
        return [
            self.encode_li_vn_mode(),
            self.stratum,
            self.poll,
            self.precision,
            self.root_delay,
            self.root_dispersion,
            self.reference_identifier,
            *self.reference_timestamp,
            *self.originate_timestamp,
            *self.receive_timestamp,
            *self.transmit_timestamp
        ]

    def get_ntp_timestamp_offset(self):
        return datetime.datetime(1900, 1, 1, tzinfo=datetime.timezone.utc).timestamp()
    
    def get_iso_format(self, timestamp):
        t = datetime.datetime.fromtimestamp(timestamp)
        return t.isoformat()

    def print_info(self):
        print("Leap Indicator: {}".format(self.li))
        print("Version Number: {}".format(self.vn))
        print("Mode: {}".format(self.mode))
        print("Stratum: {}".format(self.stratum))
        print("Poll Interval: {}".format(self.poll))
        print("Precision: {}".format(self.precision))
        print("Root Delay: {}".format(self.root_delay))
        print("Root Dispersion: {}".format(self.root_dispersion))
        print("Reference Identifier: {}".format(self.reference_identifier))
        print("Reference Timestamp: {}".format(self.get_iso_format(self.decode_ntp_timestamp(*self.reference_timestamp))))
        print("Originate Timestamp: {}".format(self.get_iso_format(self.decode_ntp_timestamp(*self.originate_timestamp))))
        print("Receive Timestamp: {}".format(self.get_iso_format(self.decode_ntp_timestamp(*self.receive_timestamp))))
        print("Transmit Timestamp: {}".format(self.get_iso_format(self.decode_ntp_timestamp(*self.transmit_timestamp))))
    
    # construct a sntp client packet
    @staticmethod
    def client_packet():
        packet = SNTP_Packet()
        packet.li = 0

        # using sntp version 4
        packet.vn = 4

        # mode 3 indicates this is a client packet
        packet.mode = 3

        curr_time = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
        packet.transmit_timestamp = packet.encode_ntp_timestamp(curr_time)
        return packet

    @staticmethod
    def compute_offset(client_transmission_time, client_reception_time, server_transmission_time, server_reception_time):
        theta_1_second = server_reception_time[0] - client_transmission_time[0]
        theta_1_fraction = (server_reception_time[1] - client_transmission_time[1]) / (2 ** 32)
        theta_2_second = server_transmission_time[0] - client_reception_time[0]
        theta_2_fraction = (server_transmission_time[1] - client_reception_time[1]) / (2 ** 32)
        return (theta_1_second + theta_1_fraction + theta_2_second + theta_2_fraction) / 2
