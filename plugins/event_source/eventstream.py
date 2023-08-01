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
  - delay (Optional): Introduce a delay between each event. Default: float(0).


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
import re
import json
import logging
from typing import Any, Callable, Dict, Optional, List, AsyncGenerator
import aiohttp
from falconpy import APIHarness

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
    def __init__(self, client: APIHarness, stream_name: str, offset: int, include_event_types: list[str], stream: dict) -> None:
        """
        Initializes a new Stream object.

        Args:
            client (APIHarness): An instance of the Falcon APIHarness client.
            stream_name (str): A label identifying the connection.
            offset (int): The offset to start streaming from.
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
        self.include_event_types: list[str] = include_event_types
        self.epoch: int = int(time.time())
        self.refresh_interval: int = int(stream["refreshActiveSessionInterval"])
        self.token_expired: Callable[[], bool] = lambda: ((self.refresh_interval) - 60) + self.epoch < int(time.time())
        self.spigot: Optional[aiohttp.ClientResponse] = None  # type: ignore
        self.eventTypeCount: Dict[str, int] = dict()

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

        loop = asyncio.get_running_loop()

        authenticated = await loop.run_in_executor(None, self.client.authenticate)

        if not authenticated:
            raise ValueError("Failed to refresh tokens. Check credentials/falcon_cloud and try again.")

        refreshed_partition = await loop.run_in_executor(
            None,
            lambda: self.client.command(
                action="refreshActiveStreamSession",
                partition=self.partition,
                parameters={"action_name": "refresh_active_stream_session", "appId": self.stream_name},
            ),
        )

        if "status_code" in refreshed_partition and refreshed_partition["status_code"] == 200:
            self.epoch = int(time.time())
            logger.info("Successfully refreshed stream %s:%s", self.stream_name, self.partition)
            refreshed = True

        return refreshed

    async def open_stream(self) -> aiohttp.ClientResponse:
        """
        Opens a long-lived async HTTP connection to the CrowdStrike Falcon Event Stream.

        Constructs the URL for the event stream using the data feed URL, offset, and event type filter. This URL is used
        to send a GET request to the server. The aiohttp.ClientSession is not managed within this function, so the caller
        must ensure that the session is properly closed after usage.

        Returns:
            aiohttp.ClientResponse: The server's response to the GET request, which is an open streaming connection.

        Raises:
            aiohttp.ClientResponseError: If the server responds with an HTTP status code that indicates an error.
            aiohttp.ClientConnectionError: If there is a problem with the underlying TCP connection.
            aiohttp.ClientTimeoutError: If the connection times out.
        """
        event_type_filter = "" if not self.include_event_types else f"&eventType={','.join(self.include_event_types)}"
        offset_filter = f"&offset={self.offset}"

        kwargs = {
            "url": f"{self.data_feed}{offset_filter}{event_type_filter}",
            "headers": {
                "Authorization": f"Token {self.token}",
            },
            "raise_for_status": True,
            "timeout": aiohttp.ClientTimeout(total=float(self.refresh_interval)),
        }

        session = aiohttp.ClientSession()
        self.spigot: aiohttp.ClientResponse = await session.get(**kwargs)
        logger.info("Successfully opened stream %s:%s", self.stream_name, self.partition)
        return self.spigot

    async def stream_events(self, exclude_event_types: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously generate events from the CrowdStrike Falcon Event Stream API.

        This method opens a stream to the Falcon API, iterates over the lines in the stream, and decodes and yields each event.
        It automatically refreshes the client token and reopens the stream if the token has expired.

        Args:
            exclude_event_types (List[str]): A list of event types to be excluded from the stream.

        Yields:
            Dict[str, Any]: A dictionary containing the event data from the Falcon API and a count of event types seen so far.

        Raises:
            aiohttp.ClientResponseError: If the server responds with an HTTP status code that indicates an error.
            ValueError: If client authentication fails during the token refresh process.
        """
        # Open the stream
        await self.open_stream()
        # Asynchronously iterate over the lines in the stream
        async for line in self.spigot.content:
            # Decode the line from bytes to a string and remove trailing whitespace
            line = line.decode().rstrip()
            if line:
                # Load the event as a JSON object
                jsonEvent = json.loads(line)
                eventType = jsonEvent["metadata"]["eventType"]
                self.offset = jsonEvent["metadata"]["offset"]
                # If the event is valid, yield it
                if self.is_valid_event(eventType, exclude_event_types):
                    # If logger is set to INFO or DEBUG, update the eventTypeCount
                    if logger.level <= logging.INFO:
                        self.eventTypeCount[eventType] = self.eventTypeCount.get(eventType, 0) + 1
                        yield dict(falcon=jsonEvent, eventTypeCount=self.eventTypeCount)
                    else:
                        yield dict(falcon=jsonEvent)
            # If the token has expired, refresh it and reopen the stream
            if self.token_expired():
                await self.refresh()
                continue

    def is_valid_event(self, event_type: str, exclude_event_types: List[str]) -> bool:
        """
        This function checks if a given event type is valid or not.

        Parameters:
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
    delay: float = float(args.get("delay", 0))
    include_event_types: List[str] = list(args.get("include_event_types", []))
    exclude_event_types: List[str] = list(args.get("exclude_event_types", []))

    if falcon_cloud not in REGIONS:
        raise ValueError(f"Invalid falcon_cloud: {falcon_cloud}, must be one of {list(REGIONS.keys())}")

    falcon: APIHarness = APIHarness(client_id=falcon_client_id,
                                    client_secret=falcon_client_secret,
                                    base_url=REGIONS[falcon_cloud],
                                    ssl_verify=True
                                    )

    loop = asyncio.get_running_loop()
    authenticated = await loop.run_in_executor(None, falcon.authenticate)

    if not authenticated:
        raise ValueError("Failed to authenticate to CrowdStrike Falcon API. Check credentials/falcon_cloud and try again.")

    availableStreams = await loop.run_in_executor(None, lambda: falcon.command(action="listAvailableStreamsOAuth2", appId=stream_name))

    if not availableStreams["body"] or not availableStreams["body"]["resources"]:
        print("Unable to open stream, no streams available. Ensure you are using a unique stream_name.")
        return

    streams: List[Stream] = [Stream(falcon, stream_name, offset, include_event_types, stream) for stream in availableStreams["body"]["resources"]]

    # Iterate over each stream in the streams list
    for stream in streams:
        try:
            async for event in stream.stream_events(exclude_event_types):
                await queue.put(event)
                await asyncio.sleep(delay)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Uncaught Plugin Task Error: %s", e)
            continue
        finally:
            logger.info("Plugin Task Finished..cleaning up")
            # Close the stream
            await stream.spigot.close()

if __name__ == "__main__":
    class MockQueue:
        """Mock Queue for testing purposes"""
        async def put(self, event) -> None:
            """Mock put method"""
            print(event)

    mock_arguments = dict()
    asyncio.run(main(MockQueue(), mock_arguments))  # type: ignore
