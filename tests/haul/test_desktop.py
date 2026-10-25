from haul.desktop import autostart_command, listening_pid


def test_listening_pid_reads_ports_in_network_order():
    # MIB_TCPTABLE_OWNER_PID : nombre de lignes, puis (état, adresse, port, adresse, port, PID)
    port_17655 = 0xF744  # 17655 = 0x44F7, octets inversés (ordre réseau)
    table = [2, 2, 0x0100007F, 0x5000, 0, 0, 111, 2, 0x0100007F, port_17655, 0, 0, 4242]
    assert listening_pid(table, 17655) == 4242
    assert listening_pid(table, 80) == 111
    assert listening_pid(table, 443) is None
    assert listening_pid([5, 2, 0], 17655) is None  # table tronquée
    assert listening_pid([], 17655) is None


def test_autostart_starts_minimized():
    assert autostart_command().endswith("--minimized")
