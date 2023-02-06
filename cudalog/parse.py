from abc import ABC, abstractmethod
from cudalog.events import Event
from cudalog.utils import trycast
from dataclasses import dataclass
from enum import IntEnum
from loguru import logger
import re


@dataclass(kw_only=True)
class Parser(ABC):
    time: str
    zone: str

    @staticmethod
    @abstractmethod
    def parse(log: dict) -> "Parser":
        raise NotImplementedError


class SeverityLevel(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    UNKNOWN = -1

    @classmethod
    def parse(cls, name: str | int):
        if isinstance(name, str):
            if (name := name.upper()) in cls.__members__.keys():
                return SeverityLevel[name]
        if (
            val := trycast(int, name, SeverityLevel.UNKNOWN.value)
        ) in cls.__members__.values():
            return SeverityLevel(val)
        return SeverityLevel.UNKNOWN


class EventAction(IntEnum):
    INSERT = 0
    SEND = 1
    DROP = 2
    ACK = 3
    UNKNOWN = -1


@dataclass
class LogEventEntry(Parser):
    action: EventAction
    layer_name: str
    class_name: str
    event_id: int
    event_name: str
    description: str = ""
    message: str = ""

    def __str__(self):
        return (
            f"@ [{self.time:<19} ({self.zone:<6})] - "
            f"{self.layer_name:<30} {self.class_name:<15} - "
            f"{self.description} {self.message}"
        )

    @staticmethod
    def parse(log: dict) -> "LogEventEntry":
        message = log.get("message")
        match = re.search("\((.*)\)", message)
        all_content = match.groups()
        content = all_content[0].split("|")
        event = Event.from_id(content[5])
        common = dict(
            layer_name=content[2],
            class_name=content[4],
            event_id=event.id,
            event_name=event.name,
            description=content[6],
            time=log.get("time"),
            zone=log.get("timezone"),
        )
        if "Insert Event from" in message:
            return LogEventEntry(
                action=EventAction.INSERT,
                message=content[9],
                **common,
            )
        elif "Drop Event from" in message:
            return LogEventEntry(
                action=EventAction.DROP,
                **common,
            )
        elif "Get ACK from" in message:
            return LogEventEntry(
                action=EventAction.ACK,
                **common,
            )
        elif "Send Event" in message:
            return LogEventEntry(
                action=EventAction.SEND,
                **common,
            )


@dataclass
class LogThreatEntry(Parser):
    severity: SeverityLevel
    threat: str = ""
    proto: str = ""
    src: str = ""
    dst: str = ""
    target: str = ""
    description: str = ""
    username: str = ""
    category: str = ""

    def __str__(self):
        return (
            f"@ [{self.time:<19} ({self.zone:<6})] - "
            f"[{self.severity.name:<7}] {self.threat:<5} {self.description:<50}"
            f"   {self.src:<16} ->   {self.dst:<21}"
            f" {self.target:<30}{(' @' + self.username) if self.username else ''}"
        )

    @staticmethod
    def parse(log: dict) -> "LogThreatEntry":
        message = log.get("message")
        try:
            msg, dsc, usr, sev, cat = message.split("|")
            _, _, _, threat, proto, src, dst, target = re.match(
                r"^(\S+): \[(\S+)\] (\S+): (\S+) (\S+) ([\d\.\:]+) \-\> ([\d\.\:]+)(?: (\S+))?(?: )?$",
                msg,
            ).groups("")
            return LogThreatEntry(
                time=log.get("time", ""),  # Time the log was received
                zone=log.get("timezone", ""),  # Timezone (offset from UTC)
                severity=SeverityLevel.parse(sev),  # (info, low, medium, high)
                threat=threat,  # Threat category/title
                proto=proto,  # Protocol (TCP, UDP, etc)
                src=src,  # IP Address source
                dst=dst,  # IP Address and port destination
                target=target,  # Resolved FQDN
                description=dsc,  # High level description of the threat
                username=usr,  # Username of the affected user if known
                category=cat or "Unknown",  # Category of the log event
            )
        except Exception as e:
            logger.exception(e)
