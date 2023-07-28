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
  - offset (Optional): The offset to start streaming from. Default: 0.
  - delay (Optional): The delay between each event. Helps to reduce overflowing the queue. Default: 0.1 seconds.


Examples:
  # Stream all events except AuthActivityAuditEvent from Falcon Event Stream API
  sources:
    - crowdstrike.falcon.eventstream:
        falcon_client_id: "{{ FALCON_CLIENT_ID }}"
        falcon_client_secret: "{{ FALCON_CLIENT_SECRET }}"
        falcon_cloud: "us-1"
        exclude_event_types:
          - "AuthActivityAuditEvent"

  # Stream only DetectionSummaryEvent from Falcon Event Stream API
  sources:
    - crowdstrike.falcon.eventstream:
        falcon_client_id: "{{ FALCON_CLIENT_ID }}"
        falcon_client_secret: "{{ FALCON_CLIENT_SECRET }}"
        falcon_cloud: "us-2"
        stream_name: "eda-example"
        include_event_types:
          - "DetectionSummaryEvent"

"""
import asyncio
import time
import datetime
import re
import json
import logging

from typing import Any, Callable, Dict, Optional, List
from falconpy import APIHarness
import requests

logger = logging.getLogger()

# Region Mapping
REGIONS: Dict[str, str] = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


class Stream():
    """Stream class for the CrowdStrike Falcon Event Stream API"""

    def __init__(self, client: APIHarness, stream_name: str, offset: int, delay: float, include_event_types: list[str], stream: dict) -> None:
        """
        Initializes a new Stream object.

        Args:
            client (APIHarness): An instance of the Falcon APIHarness client.
            stream_name (str): A label identifying the connection.
            offset (int): The offset to start streaming from.
            delay (float): The delay between each event to help reduce overflowing the queue.
            include_event_types (List[str]): A list of event types to filter on.
            stream (Dict): A dictionary containing the details of the stream.

        Raises:
            ValueError: If the 'refreshActiveSessionURL' in the stream dictionary does not contain a numeric partition value.
        """
        print(f"Initializing Stream: {stream_name}")
        self.client: APIHarness = client
        self.stream_name: str = stream_name
        self.data_feed: str = stream["dataFeedURL"]
        self.token: str = stream["sessionToken"]["token"]
        self.token_expires: str = stream["sessionToken"]["expiration"]
        self.refresh_url: str = stream['refreshActiveSessionURL']
        self.partition: str = re.findall(r'v1/(\d+)', self.refresh_url)[0]
        self.offset: int = offset
        self.delay: float = delay
        self.include_event_types: list[str] = include_event_types
        self.epoch: int = int(time.time())
        self.refresh_interval: int = int(stream["refreshActiveSessionInterval"])
        self.token_expired: Callable[[], bool] = lambda: ((self.refresh_interval) - 60) + self.epoch < int(time.time())
        self.spigot: Optional[requests.Response] = None  # type: ignore

    async def refresh(self) -> bool:
        """
        Refreshes the stream and client token.

        This method authenticates the client, and if authentication is successful, it refreshes the active stream
        session.

        Raises:
            ValueError: If client authentication fails.

        Returns:
            bool: True if the refresh was successful (i.e., the server responded with a status code of 200); False
            otherwise.
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
            self.epoch = int(time.time())
            logger.info("Successfully refreshed stream %s:%s", self.stream_name, self.partition)
            refreshed = True

        return refreshed

    async def open_stream(self) -> requests.Response:
        """
        Opens a long lived HTTP connection to the CrowdStrike Falcon Event Stream.

        Constructs the URL for the event stream using the data feed URL, offset, and event type filter. This URL is used
        to send a GET request to the server.

        Returns:
            requests.Response: The server's response to the GET request.

        Raises:
            requests.HTTPError: If the server responds with an HTTP status code that indicates an error.
        """
        eventTypeFilter = '' if self.include_event_types is None else '&eventType=' + ','.join(self.include_event_types)

        kwargs = {
            "url": self.data_feed + '&offset={}'.format(self.offset) + eventTypeFilter,
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

    async def stream_events(self, queue: asyncio.Queue, stop_event: asyncio.Event, exclude_event_types: List[str]) -> None:
        """
        Stream events from the CrowdStrike Falcon Event Stream API to a queue.

        This method opens the event stream, then continually reads from it. For each line read from the stream:
        - If the `stop_event` is set, the method immediately stops reading from the stream and returns.
        - If the line is not empty, the method decodes the line into a JSON object and extracts the event type and offset.
        - If the event type is valid and not in the exclude list, the JSON object is added to the queue.
        - The method then sleeps for a short time to allow for other tasks to run.
        - If the API token has expired, it is refreshed.

        If at any point the stream becomes unreadable, the method stops reading from the stream and returns.

        Args:
            queue (asyncio.Queue): The queue to which JSON objects representing valid events will be added.
            stop_event (asyncio.Event): An event that, if set, will cause the method to stop reading from the stream.
            exclude_event_types (List[str]): A list of event types to exclude. Events of these types will not be added to the queue.

        Returns:
            None
        """
        stream: requests.Response = await self.open_stream()

        # Create a way to keep track of the eventType's by count for debugging purposes
        eventTypeCount = dict()

        for line in stream.iter_lines():
            if stop_event.is_set():
                break
            if line:
                jsonEvent = json.loads(line.decode("utf-8"))
                eventType = jsonEvent["metadata"]["eventType"]
                self.offset = jsonEvent["metadata"]["offset"]

                if self.is_valid_event(eventType, exclude_event_types):
                    eventTypeCount[eventType] = eventTypeCount.get(eventType, 0) + 1
                    logger.info("EventType(s) by count: %s", eventTypeCount)
                    await queue.put(dict(falcon=jsonEvent))
                    await asyncio.sleep(self.delay)
            if self.token_expired():
                await self.refresh()
                continue
            if not stream.raw.readable():
                break

    def is_valid_event(self, event_type: str, exclude_event_types: List[str]) -> bool:
        """
        This function checks if a given event type is valid or not.

        Args:
            event_type (str): The type of the event to be checked.
            exclude_event_types (List[str]): A list of event types to be excluded.

        Returns:
            bool: Returns False if the event_type is in the exclude_event_types list, otherwise returns True.
        """
        if event_type in exclude_event_types:
            return False
        return True


async def main(queue: asyncio.Queue, args: Dict[str, Any]) -> None:
    """
    Main function for the eventstream event_source plugin

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
    offset: int = int(args.get("offset", 0))
    delay: float = float(args.get("delay", 0.1))
    include_event_types: List[str] = list(args.get("include_event_types", []))
    exclude_event_types: List[str] = list(args.get("exclude_event_types", []))

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
        availableStreams = falcon.command(action="listAvailableStreamsOAuth2", appId=stream_name)

        if not availableStreams["body"] or not availableStreams["body"]["resources"]:
            print("Unable to open stream, no streams available. Ensure you are using a unique stream_name.")
            return

        streams: List[Stream] = []
        for stream in availableStreams["body"]["resources"]:
            streams.append(Stream(falcon, stream_name, offset, delay, include_event_types, stream))

        # Create an asyncio Queue with a size equal to the number of streams
        q: asyncio.Queue = asyncio.Queue(len(streams))

        # Create a list of tasks. Each task is responsible for streaming events from a stream
        # and putting them into the queue.
        tasks = [asyncio.create_task(stream.stream_events(q, stop_event, exclude_event_types)) for stream in streams]

        # Keep taking events from the queue and putting them into another queue as long as the stop_event is not set
        while not stop_event.is_set():
            event = await q.get()
            await queue.put(event)

        # After the while loop, then you can await the tasks
        await asyncio.gather(*tasks)

    except asyncio.CancelledError:
        logger.error("Plugin Task Cancelled")
    except Exception as e:
        logger.error("Uncaught Plugin Task Error: %s", e)
        raise
    finally:
        stop_event.set()
        logger.info("Plugin Task Finished")


if __name__ == "__main__":

    class MockQueue:
        """Mock Queue for testing purposes
        """
        async def put(self, event) -> None:
            """Mock put method"""
            print(event)

    mock_arguments = dict()
    asyncio.run(main(MockQueue(), mock_arguments))  # type: ignore
