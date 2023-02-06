from cudalog.parse import LogThreatEntry, LogEventEntry
from dataclasses import dataclass
from datetime import datetime as dt, timedelta as td
from typing import Optional
import aiohttp
import urllib


DEFAULT_DELTA = td(hours=24)


class NGFWAPI:
    """For generating URL's"""

    def __init__(self, host: str, port: str, version: str = "v1"):
        self.url = f"https://{host}:{port}"
        self.ver = version

    def _log(self, suffix: str | None = None) -> str:
        url = f"{self.url}/rest/log/{self.ver}/files"
        return url if suffix is None else f"{url}/{suffix}"

    @property
    def logs(self):
        return self._log()

    @property
    def logs_threat(self):
        return self._log("box_Firewall_threat/filter")

    @property
    def logs_events(self):
        return self._log("box_Event_eventS/filter")


@dataclass
class NGFW_Response:
    url: str
    code: Optional[int]
    data: Optional[object] = None
    exception: Optional[Exception] = None

    @property
    def success(self) -> bool:
        return self.exception is None and self.code // 100 == 2

    @property
    def failure(self):
        return self.exception is not None


class NGFW:
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        api_key: str,
        timeout_connect: td = td(seconds=5),
        timeout_read: td = td(seconds=60),
        ssl_settings: dict = None,
    ):
        self._name = name
        self._host = host
        self._port = port
        self._api = NGFWAPI(host, port)
        self._api_key = api_key
        self._timeout = aiohttp.ClientTimeout(
            connect=timeout_connect.total_seconds(),
            sock_read=timeout_read.total_seconds(),
        )
        self._ssl_settings = ssl_settings

    @property
    def name(self):
        return self._name

    @property
    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "X-API-Token": self._api_key,
        }

    @staticmethod
    def _encode(data: object) -> str:
        return urllib.parse.urlencode(data, safe=":")

    async def _post(self, url: str, data: Optional[dict] = None):
        try:
            data = data if data is not None else dict()
            async with aiohttp.ClientSession(
                headers=self._headers,
                connector=aiohttp.TCPConnector(verify_ssl=False),
                timeout=self._timeout,
            ) as session:
                async with session.post(url, json=data) as r:
                    return NGFW_Response(
                        url=url,
                        data=await r.json(),
                        code=r.status,
                        exception=None,
                    )
        except Exception as e:
            return NGFW_Response(
                url=url,
                data=None,
                code=None,
                exception=e,
            )

    async def _get(self, url: str, params: Optional[dict] = None):
        try:
            params = params if params is not None else dict()
            async with aiohttp.ClientSession(
                headers=self._headers,
                connector=aiohttp.TCPConnector(verify_ssl=False),
            ) as session:
                async with session.get(url, params=self._encode(params)) as r:
                    return await r.json()
        except Exception as e:
            return NGFW_Response(
                url=url,
                code=None,
                data=None,
                exception=e,
            )

    @staticmethod
    def timefmt(t: dt) -> str:
        return t.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def times(delta: td, t: Optional[dt] = None):
        if t is None:
            t = dt.now()
        return {"from": NGFW.timefmt(t - delta), "to": NGFW.timefmt(t)}

    async def get_logs_events(
        self, delta: td = DEFAULT_DELTA, insert_only: bool = False
    ):
        data = {**self.times(delta)}
        if insert_only:
            data["filter"] = {
                "caseSensitive": True,
                "matchAll": True,
                "messageConditions": [
                    {
                        "exclude": False,
                        "query": "Insert Event",
                    }
                ],
            }
        response = await self._post(self._api.logs_events, data=data)
        if not response.success:
            raise response.exception
        else:
            return [
                entry
                for log in response.data.get("content", [])
                if (entry := LogEventEntry.parse(log)) is not None
            ]

    async def get_logs_threat(self, delta: td = DEFAULT_DELTA):
        data = {**self.times(delta)}
        response = await self._post(self._api.logs_threat, data=data)
        if not response.success:
            raise response.exception
        else:
            return [
                entry
                for log in response.data.get("content", [])
                if (entry := LogThreatEntry.parse(log)) is not None
            ]

        # return list(
        #     filter(
        #         lambda x: x is not None,
        #         (
        #             LogThreatEntry.parse(log)
        #             for log in (
        #                 (
        #                     await self._post(
        #                         self._api.logs_threat,
        #                         data=data,
        #                     )
        #                 ).data.get("content")
        #             )
        #         ),
        #     )
        # )
