"""
eventstream.py

An ansible-rulebook event source plugin for generating events from the Falcon Event Stream API

Each event is imbedded in a dict with the key "falcon" and the value is the raw event from the API.

Example:
    {
        "falcon": {
            ...api event...
        }
    }

Arguments:
  - falcon_client_id: CrowdStrike OAUTH Client ID
  - falcon_client_secret: CrowdStrike OAUTH Client Secret
  - falcon_cloud: CrowdStrike Cloud Region (us-1, us-2, eu-1, us-gov-1) Default: us-1
  - stream_name (Optional): Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9) Default: eda.
  - include_event_types (Optional): List of event types to filter on. Default: All event types.
  - exclude_event_types (Optional): List of event types to exclude. Default: None.


Examples:
  sources:
    - crowdstrike.falcon.eventstream:
        falcon_client_id: "{{ lookup('env', 'FALCON_CLIENT_ID') }}"
        falcon_client_secret: "{{ lookup('env', 'FALCON_CLIENT_SECRET') }}"
        falcon_cloud: "us-1"
        include_event_types:
            - "UserActivityAuditEvent"
        exclude_event_types:
            - "AuthActivityAuditEvent"


"""
import asyncio
import time
import datetime
import re
import json

from typing import Any, Callable, Dict, Optional, List
from falconpy import APIHarness
import requests


class Stream():
    """Stream class for the CrowdStrike Falcon Event Stream API
    """

    def __init__(self, client: APIHarness, stream_name: str, stream: dict) -> None:
        print(f"Initializing Stream: {stream_name}")
        self.client: APIHarness = client
        self.stream_name: str = stream_name
        self.data_feed: str = stream["dataFeedURL"]
        self.token: str = stream["sessionToken"]["token"]
        self.token_expires: str = stream["sessionToken"]["expiration"]
        self.refresh_url: str = stream['refreshActiveSessionURL']
        self.partition: str = re.findall(r'v1/(\d+)', self.refresh_url)[0]
        self.offset: str = ""
        self.epoch: int = int(time.time())
        self.refresh_interval: int = int(stream["refreshActiveSessionInterval"])
        self.token_expired: Callable[[], bool] = lambda: ((self.refresh_interval) - 60) + self.epoch < int(time.time())
        self.spigot: Optional[requests.Response] = None  # type: ignore

    async def refresh(self) -> bool:
        """Refresh the stream and client token
        """
        refreshed: bool = False

        self.client.authenticate()

        if not self.client.authenticated:
            raise ValueError("Failed to refresh tokens. Check credentials/falcon_cloud and try again.")

        refreshed_partition = self.client.command(action="refreshActiveStreamSession", partition=self.partition, parameters={
            "action_name": "refresh_active_stream_session",
            "appId": self.stream_name,
        })

        if "status_code" in refreshed_partition and refreshed_partition["status_code"] == 200:
            self.token = refreshed_partition["body"]["sessionToken"]["token"]
            self.token_expires = refreshed_partition["body"]["sessionToken"]["expiration"]
            self.refresh_url = refreshed_partition["body"]["refreshActiveSessionURL"]
            self.refresh_interval = int(refreshed_partition["body"]["refreshActiveSessionInterval"])
            self.partition = re.findall(r'v1/(\d+)', self.refresh_url)[0]
            refreshed = True

        return refreshed

    async def open_stream(self) -> requests.Response:
        """Open the event stream

        Returns:
            requests.Response: The open stream
        """
        kwargs = {
            "url": self.data_feed,
            "headers": {
                "Authorization": f"Token {self.token}",
                'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000'),
                "Connection": "keep-alive",
            },
            "stream": True,
            "verify": True,
        }

        self.spigot: requests.Response = requests.get(**kwargs, timeout=self.refresh_interval)
        self.spigot.raise_for_status()
        return self.spigot

    async def stream_events(self, queue: asyncio.Queue, stop_event: asyncio.Event, include_event_types: List[str], exclude_event_types: List[str]) -> None:
        """Stream events from the CrowdStrike Falcon Event Stream API

        Args:
            queue (asyncio.Queue): The queue to send events to
        """
        stream: requests.Response = await self.open_stream()

        for line in stream.iter_lines():
            if stop_event.is_set():
                break
            if line:
                jsonEvent = json.loads(line.decode("utf-8"))
                eventType = jsonEvent["metadata"]["eventType"].lower()
                self.offset = jsonEvent["metadata"]["offset"]

                valid: bool = True

                if include_event_types and eventType not in include_event_types:
                    valid = False

                if exclude_event_types and eventType in exclude_event_types:
                    valid = False

                if valid:
                    await queue.put(dict(falcon=jsonEvent))
            if self.token_expired():
                await self.refresh()
                continue
            if not stream.raw.readable():
                break


# Region Mapping
# TODO: Should Region be "cloud" and should falcon_cloud be falcon_region?
REGIONS: Dict[str, str] = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


async def main(queue: asyncio.Queue, args: Dict[str, Any]) -> None:
    """Main function for the eventstream event_source plugin

    Args:
        queue (asyncio.Queue): The queue to send events to
        args (Dict[str, Any]): The event_source arguments

    Raises:
        ValueError: If a argument is invalid
    """
    falcon_client_id: str = str(args.get("falcon_client_id"))
    falcon_client_secret: str = str(args.get("falcon_client_secret"))
    falcon_cloud: str = str(args.get("falcon_cloud", "us-1"))
    stream_name: str = str(args.get("stream_name", "eda")).lower()
    include_event_types: List[str] = list(args.get("include_event_types", []))
    exclude_event_types: List[str] = list(args.get("exclude_event_types", []))

    include_event_types = [x.lower() for x in include_event_types]
    exclude_event_types = [x.lower() for x in exclude_event_types]

    if falcon_cloud not in REGIONS:
        raise ValueError(f"Invalid falcon_cloud: {falcon_cloud}, must be one of {list(REGIONS.keys())}")

    falcon: APIHarness = APIHarness(client_id=falcon_client_id,
                                    client_secret=falcon_client_secret,
                                    base_url=REGIONS[falcon_cloud],
                                    ssl_verify=True
                                    )

    if not falcon.authenticate():
        raise ValueError("Failed to authenticate to CrowdStrike Falcon API. Check credentials/falcon_cloud and try again.")

    stop_event: asyncio.Event = asyncio.Event()

    try:
        q: asyncio.Queue = asyncio.Queue(10)

        availableStreams = falcon.command(action="listAvailableStreamsOAuth2", appId=stream_name)

        if not availableStreams["body"] or not availableStreams["body"]["resources"]:
            print("Unable to open stream, no streams available. Ensure you are using a unique stream_name.")
            return

        streams: List[Stream] = []
        for stream in availableStreams["body"]["resources"]:
            streams.append(Stream(falcon, stream_name, stream))

        tasks = [asyncio.create_task(stream.stream_events(q, stop_event, include_event_types, exclude_event_types)) for stream in streams]

        while not stop_event.is_set():
            event = await q.get()
            await queue.put(event)

        await asyncio.gather(*tasks)

    except asyncio.CancelledError:
        print("Plugin Task Cancelled")
    except Exception as e:
        print(f"Uncaught Plugin Task Error: {e}")
        raise
    finally:
        stop_event.set()
        print("Plugin Task Finished")


if __name__ == "__main__":

    class MockQueue:
        """Mock Queue for testing purposes
        """
        async def put(self, event) -> None:
            """Mock put method"""
            print(event)

    mock_arguments = dict()
    asyncio.run(main(MockQueue(), mock_arguments))  # type: ignore
