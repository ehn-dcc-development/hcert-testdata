from typing import Optional

import serial


class SerialScanner:
    """Serial scanner"""

    def __init__(self, port: str, baudrate: Optional[int] = None) -> None:
        self.scanner = serial.Serial(port=port, baudrate=baudrate or 115200)

    def read(self) -> Optional[bytes]:
        """Read data from scanner"""
        waiting = self.scanner.inWaiting()
        if waiting > 0:
            data = self.scanner.read(waiting)
            return data
        return None

    def write(self, data: bytes) -> None:
        """Write data to scanner"""
        self.scanner.write(data)


class AccessIsAtr110(SerialScanner):
    def __init__(self, port: str, baudrate: Optional[int] = None) -> None:
        super().__init__(port, baudrate)
        self.send_modify_command("AISRDS", 1)
        self.send_modify_command("ALLENA", 1)

    def send_command(self, command: str) -> bytes:
        """Send command to scanner, return any resulting data"""
        prefix = [0x16, 0x4D, 0x0D]
        data = bytes(prefix) + command.encode()
        self.write(data)
        return self.read()

    def send_modify_command(
        self, command: str, parameter=None, permanent: bool = False
    ):
        """Send modify command to scanner"""
        if permanent:
            # modify a setting permanently
            terminator = "."
        else:
            # modify a setting temporarily
            terminator = "!"
        if parameter is not None:
            self.send_command(command + str(parameter) + terminator)
        else:
            self.send_command(command + terminator)
