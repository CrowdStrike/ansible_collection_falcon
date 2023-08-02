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

logger = logging.getLogger()

# Region Mapping
REGIONS: Dict[str, str] = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


class AIOFalconAPI:
    """
    An asynchronous API client for the CrowdStrike Falcon Event Stream API.

    This client uses the aiohttp library to make asynchronous HTTP requests to the Falcon API. It includes methods for
    authenticating to the API, listing available streams, and refreshing a stream.

    Attributes:
        BASE_URL (str): The base URL for the Falcon API.
        TOKEN_URL (str): The endpoint for obtaining an access token.
        LIST_STREAMS_URL (str): The endpoint for listing available streams.
        REFRESH_STREAM_URL (str): The endpoint for refreshing a stream.
        client_id (str): The client ID for authenticating to the Falcon API.
        client_secret (str): The client secret for authenticating to the Falcon API.
        base_url (str, optional): The base URL for the Falcon API. Defaults to BASE_URL.
        session (aiohttp.ClientSession): The aiohttp client session for making HTTP requests.

    Methods:
        close: Close the aiohttp client session.
        authenticate: Authenticate to the Falcon API and return the access token.
        list_available_streams: List available streams from the Falcon API.
        refresh_stream: Refresh a stream from the Falcon API.
    """
    BASE_URL = "https://api.crowdstrike.com"
    TOKEN_URL = "/oauth2/token"
    LIST_STREAMS_URL = "/sensors/entities/datafeed/v2"
    REFRESH_STREAM_URL = "/sensors/entities/datafeed-actions/v1/{partition}"

    def __init__(self, client_id: str, client_secret: str, base_url: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url or self.BASE_URL
        self.session = aiohttp.ClientSession()

    async def close(self):
        """Close the aiohttp session"""
        await self.session.close()

    async def authenticate(self) -> str:
        """
        Authenticate to the CrowdStrike Falcon API and return the access token.

        This method sends a POST request to the Falcon API's authentication endpoint, passing the client ID and
        secret in the request body. If authentication is successful, it returns the access token provided by the API.

        Returns:
            str: The access token provided by the Falcon API.
        """
        url = self.base_url + self.TOKEN_URL
        data = {"client_id": self.client_id, "client_secret": self.client_secret}
        async with self.session.post(url, data=data) as resp:
            result = await resp.json()
            if not result.get("access_token"):
                raise ValueError("Failed to authenticate to CrowdStrike Falcon API. Check credentials/falcon_cloud and try again.")
            return result["access_token"]

    async def list_available_streams(self, token: str, app_id: str) -> Dict:
        """
        List available streams from Event Stream API.

        This method sends a GET request to the Falcon API's endpoint for listing available streams, passing the
        app_id as a parameter in the request.

        Args:
            token (str): The access token for the Falcon API.
            app_id (str): The ID of the app for which to list available streams.

        Returns:
            dict: The JSON response from the Falcon API, which includes details about the available streams.
        """
        params = {"appId": app_id}
        url = self.base_url + self.LIST_STREAMS_URL
        headers = {"Authorization": "Bearer " + token}
        async with self.session.get(url, headers=headers, params=params) as resp:
            return await resp.json()

    async def refresh_stream(self, token: str, partition: str, app_id: str) -> bool:
        """
        Refresh a stream from Event Stream API.

        This method sends a POST request to the Falcon API's endpoint for refreshing a stream, passing the
        action_name and app_id as parameters in the request.

        Args:
            token (str): The access token for the Falcon API.
            partition (str): The partition ID of the stream to refresh.
            app_id (str): The ID of the app for which to refresh the stream.

        Returns:
            bool: True if the refresh was successful (i.e., the server responded with a status code of 200); False
        """
        params = {
            "action_name": "refresh_active_stream_session",
            "appId": app_id,
        }
        url = self.base_url + self.REFRESH_STREAM_URL.format(partition=partition)
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            }
        async with self.session.post(url, headers=headers, params=params) as resp:
            return resp.status == 200


class Stream():
    """Stream class for the CrowdStrike Falcon Event Stream API"""
    def __init__(self, client: AIOFalconAPI, stream_name: str, offset: int, include_event_types: list[str], stream: dict) -> None:
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
        self.client: AIOFalconAPI = client
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
        self.token_expired: Callable[[], bool] = lambda: ((self.refresh_interval) - 29*60) + self.epoch < int(time.time())
        self.spigot: Optional[aiohttp.ClientResponse] = None  # type: ignore

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

        token = await self.client.authenticate()
        refreshed_partition: bool = await self.client.refresh_stream(token, self.partition, self.stream_name)

        if refreshed_partition:
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
                json_event = json.loads(line)
                event_type = json_event["metadata"]["eventType"]
                self.offset = json_event["metadata"]["offset"]
                # If the event is valid, yield it
                if self.is_valid_event(event_type, exclude_event_types):
                    yield dict(falcon=json_event)
            # If the token has expired, refresh it and reopen the stream
            if self.token_expired():
                refresh = await self.refresh()
                if refresh:
                    continue
                else:
                    raise ValueError("Failed to refresh token.")

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

    falcon = AIOFalconAPI(client_id=falcon_client_id, client_secret=falcon_client_secret, base_url=REGIONS[falcon_cloud])

    token = await falcon.authenticate()
    available_streams = await falcon.list_available_streams(token, stream_name)

    if not available_streams["resources"]:
        print("Unable to open stream, no streams available. Ensure you are using a unique stream_name.")
        return

    streams: List[Stream] = [Stream(falcon, stream_name, offset, include_event_types, stream) for stream in available_streams["resources"]]

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
            # Close the API session
            await falcon.close()

if __name__ == "__main__":
    class MockQueue:
        """Mock Queue for testing purposes"""
        async def put(self, event) -> None:
            """Mock put method"""
            print(event)

    mock_arguments = dict()
    asyncio.run(main(MockQueue(), mock_arguments))  # type: ignore
