from iputils import *
import ipaddress


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            header_checksum = 0

            if ttl > 1:
                source_address = int(ipaddress.ip_address(src_addr))
                destination_address = int(ipaddress.ip_address(dst_addr))
                ttl = ttl - 1

                datagrama = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp, len(datagrama), identification, flags, ttl,
                                        proto, header_checksum, source_address, destination_address)

                header_checksum = calc_checksum(datagrama)

                datagrama = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp, len(datagrama), identification, flags, ttl,
                                        proto, header_checksum, source_address, destination_address)

                datagrama += payload

                self.enlace.enviar(datagrama, next_hop)

            else:
                ttl = 64
                proto = IPPROTO_ICMP
                next_hop = self._next_hop(src_addr)
                source_address = int(ipaddress.ip_address(self.meu_endereco))
                destination_address = int(ipaddress.ip_address(src_addr))

                datagrama_ttt0 = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp, 48, identification, flags, ttl, proto,
                                             header_checksum, source_address, destination_address)

                header_checksum = calc_checksum(datagrama_ttt0)
                datagrama_ttt0 = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp, 48, identification, flags, ttl, proto,
                                             header_checksum, source_address, destination_address)

                icmp = struct.pack('!BBHHH', 11, 0, 0, 0, 0)
                header_checksum = calc_checksum(icmp + datagrama_ttt0)
                icmp = struct.pack('!BBHHH', 11, 0, header_checksum, 0, 0)
                datagrama = datagrama_ttt0 + icmp + datagrama[:28]
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        """
        Usa a tabela de encaminhamento para determinar o próximo salto.
        """
        dest_ip = ipaddress.IPv4Address(dest_addr)

        for network, next_hop in self.tabela:
            if dest_ip in network:
                return next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # Pré-processa a tabela de encaminhamento, convertendo os CIDRs para IPv4Network
        # e ordenando por comprimento de prefixo em ordem decrescente.
        self.tabela = sorted(
            [(ipaddress.IPv4Network(cidr), next_hop) for cidr, next_hop in tabela],
            key=lambda x: x[0].prefixlen,
            reverse=True
        )

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        versao_ihl = (4 << 4) + 5
        dscp = 0
        total_length = 20 + len(segmento)
        identification = self.id
        flags = 0
        ttl = 64
        protocol = IPPROTO_TCP
        header_checksum = 0
        source_address = int(ipaddress.ip_address(self.meu_endereco))
        destination_address = int(ipaddress.ip_address(dest_addr))

        # Monta o cabeçalho IP (sem checksum)
        datagrama = struct.pack('!BBHHHBBHII', versao_ihl, dscp, total_length, identification, flags, ttl, protocol,
                                header_checksum, source_address, destination_address)

        header_checksum = calc_checksum(datagrama)
        # Monta o cabeçalho IP com o checksum
        datagrama = struct.pack('!BBHHHBBHII', versao_ihl, dscp, total_length, identification, flags, ttl, protocol,
                                header_checksum, source_address, destination_address)

        datagrama += segmento
        # Envia o datagrama para o next_hop
        self.enlace.enviar(datagrama, next_hop)
        self.id += 1
