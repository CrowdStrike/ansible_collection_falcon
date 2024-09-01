"""eventstream.py.

An ansible-rulebook event source plugin for generating events from the Falcon
Event Stream API.

Each event is imbedded in a dict with the key "falcon" and the value is the raw
event from the API.

Arguments:
---------
    falcon_client_id:       CrowdStrike OAUTH Client ID
    falcon_client_secret:   CrowdStrike OAUTH Client Secret
    falcon_cloud:           CrowdStrike Cloud Region (us-1, us-2, eu-1, us-gov-1)
                            Default: us-1
    stream_name:            Label that identifies your connection.
                            Max: 32 alphanumeric characters. Default: eda
    include_event_types:    List of event types to filter on. Defaults.
    exclude_event_types:    List of event types to exclude. Default: None.
    offset:                 The offset to start streaming from. Default: None.
    latest:                 Start stream at the latest event. Default: False.
    delay:                  Introduce a delay between each event. Default: float(0).


Examples:
--------
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
import json
import logging
import re
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any, Optional

import aiohttp

logger = logging.getLogger()

# Region Mapping
REGIONS: dict[str, str] = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

# Keep this in sync with galaxy.yml
VERSION = "4.2.1"


class AIOFalconAPI:
    """An asynchronous API client for the CrowdStrike Falcon Event Stream API.

    This client uses the aiohttp library to make asynchronous HTTP requests to
    the Falcon API. It includes methods for authenticating to the API, listing
    available streams, and refreshing a stream.

    Attributes
    ----------
        BASE_URL (str): The base URL for the Falcon API.
        TOKEN_URL (str): The endpoint for obtaining an access token.
        LIST_STREAMS_URL (str): The endpoint for listing available streams.
        REFRESH_STREAM_URL (str): The endpoint for refreshing a stream.
        client_id (str): The client ID for authenticating to the Falcon API.
        client_secret (str): The client secret for authenticating to the Falcon API.
        base_url (str, optional): The base URL for the Falcon API. Defaults to BASE_URL.
        session (aiohttp.ClientSession): The aiohttp client session for making HTTP requests.

    Methods
    -------
        close: Close the aiohttp client session.
        authenticate: Authenticate to the Falcon API and return the access token.
        list_available_streams: List available streams from the Falcon API.
        refresh_stream: Refresh a stream from the Falcon API.

    """

    BASE_URL = "https://api.crowdstrike.com"
    TOKEN_URL = "/oauth2/token"  # noqa: S105
    LIST_STREAMS_URL = "/sensors/entities/datafeed/v2"
    REFRESH_STREAM_URL = "/sensors/entities/datafeed-actions/v1/{partition}"

    def __init__(
        self: "AIOFalconAPI",
        client_id: str,
        client_secret: str,
        base_url: Optional[str] = None,
    ) -> None:
        """Initialize a new AIOFalconAPI object.

        Parameters
        ----------
        client_id: str
            The client ID for authenticating to the Falcon API.
        client_secret: str
            The client secret for authenticating to the Falcon API.
        base_url: str, optional
            The base URL for the Falcon API. Defaults to BASE_URL.

        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url or self.BASE_URL
        self.session = aiohttp.ClientSession(headers={
            "User-Agent": f"crowdstrike-ansible/eda/{VERSION}",
        })

    async def close(self: "AIOFalconAPI") -> None:
        """Close the aiohttp session."""
        await self.session.close()

    async def authenticate(self: "AIOFalconAPI") -> str:
        """Authenticate to the CrowdStrike Falcon API and return the access token.

        This method sends a POST request to the Falcon API's authentication endpoint,
        passing the client ID and secret in the request body. If authentication is
        successful, it returns the access token provided by the API.

        Returns
        -------
        str
            The access token provided by the Falcon API.

        Raises
        ------
        ValueError
            If the credentials passed fail to authenticate.

        """
        url = self.base_url + self.TOKEN_URL
        data = {"client_id": self.client_id, "client_secret": self.client_secret}
        async with self.session.post(url, data=data) as resp:
            result = await resp.json()
            if not result.get("access_token"):
                msg = "Failed to authenticate to CrowdStrike Falcon API. Check credentials/falcon_cloud and try again."
                raise ValueError(msg)
            return result["access_token"]

    async def list_available_streams(
        self: "AIOFalconAPI",
        token: str,
        app_id: str,
    ) -> dict:
        """List available streams from Event Stream API.

        This method sends a GET request to the Falcon API's endpoint for listing
        available streams, passing the app_id as a parameter in the request.

        Parameters
        ----------
        token: str
            The access token for the Falcon API.
        app_id: str
            The ID of the app for which to list available streams.

        Returns
        -------
        dict
            The JSON response from the Falcon API, which includes details about
            the available streams.

        """
        params = {"appId": app_id}
        url = self.base_url + self.LIST_STREAMS_URL
        headers = {"Authorization": "Bearer " + token}
        async with self.session.get(url, headers=headers, params=params) as resp:
            return await resp.json()

    async def refresh_stream(
        self: "AIOFalconAPI",
        token: str,
        partition: str,
        app_id: str,
    ) -> bool:
        """Refresh a stream from Event Stream API.

        This method sends a POST request to the Falcon API's endpoint for refreshing
        a stream, passing the action_name and app_id as parameters in the request.

        Parameters
        ----------
        token: str
            The access token for the Falcon API.
        partition: str
            The partition ID of the stream to refresh.
        app_id: str
            The ID of the app for which to refresh the stream.

        Returns
        -------
        bool
            True if the refresh was successful (i.e., the server responded with
            a status code of 200); False

        """
        ok_response = 200
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
            return resp.status == ok_response


class Stream:
    """Stream class for the CrowdStrike Falcon Event Stream API."""

    def __init__(
        self: "Stream",
        client: AIOFalconAPI,
        stream_name: str,
        offset: Optional[int],
        latest: bool,
        include_event_types: list[str],
        stream: dict,
    ) -> None:
        """Initialize a new Stream object.

        Parameters
        ----------
        client: AIOFalconAPI
            An instance of the Falcon APIHarness client.
        stream_name: str
            A label identifying the connection.
        offset: int
            The offset to start streaming from.
        latest: bool
            Start stream at the latest event.
        include_event_types: List[str]
            A list of event types to filter on.
        stream: dict
            A dictionary containing the details of the stream.

        """
        logger.info("Initializing Stream: %s", stream_name)
        self.client: AIOFalconAPI = client
        self.session: aiohttp.ClientSession = client.session
        self.stream_name: str = stream_name
        self.data_feed: str = stream["dataFeedURL"]
        self.token: str = stream["sessionToken"]["token"]
        self.refresh_url: str = stream["refreshActiveSessionURL"]
        self.partition: str = re.findall(r"v1/(\d+)", self.refresh_url)[0]
        self.offset: int = offset if offset else 0
        self.latest: bool = latest
        self.include_event_types: list[str] = include_event_types
        self.epoch: int = int(time.time())
        self.refresh_interval: int = int(stream["refreshActiveSessionInterval"])
        self.token_expired: Callable[[], bool] = lambda: (
            (self.refresh_interval) - 60
        ) + self.epoch < int(time.time())
        self.spigot: Optional[aiohttp.ClientResponse] = None

    async def refresh(self: "Stream") -> bool:
        """Refresh the stream and client token.

        This method authenticates the client, and if authentication is successful,
        it refreshes the active stream session.

        Returns
        -------
        bool
            True if the refresh was successful (i.e., the server responded with a
            status code of 200); False otherwise.

        """
        refreshed: bool = False

        token = await self.client.authenticate()
        refreshed_partition: bool = await self.client.refresh_stream(
            token,
            self.partition,
            self.stream_name,
        )

        if refreshed_partition:
            self.epoch = int(time.time())
            logger.info(
                "Successfully refreshed stream %s:%s",
                self.stream_name,
                self.partition,
            )
            refreshed = True

        return refreshed

    async def open_stream(self: "Stream") -> aiohttp.ClientResponse:
        """Open a long-lived async HTTP connection to the CrowdStrike Falcon Event Stream.

        Constructs the URL for the event stream using the data feed URL, offset, and
        event type filter. This URL is used to send a GET request to the server. The
        aiohttp.ClientSession is not managed within this function, so the caller must
        ensure that the session is properly closed after usage.

        Returns
        -------
        aiohttp.ClientResponse
            The server's response to the GET request, which is an open streaming
            connection.

        """
        event_type_filter = (
            ""
            if not self.include_event_types
            else f"&eventType={','.join(self.include_event_types)}"
        )
        offset_filter = "&whence=2" if self.latest else f"&offset={self.offset}"

        kwargs = {
            "url": f"{self.data_feed}{offset_filter}{event_type_filter}",
            "headers": {
                "Authorization": f"Token {self.token}",
            },
            "raise_for_status": True,
            "timeout": aiohttp.ClientTimeout(total=None),
        }

        self.spigot: aiohttp.ClientResponse = await self.session.get(**kwargs)
        logger.info(
            "Successfully opened stream %s:%s",
            self.stream_name,
            self.partition,
        )
        logger.debug("Stream URL: %s", kwargs["url"])
        return self.spigot

    async def stream_events(
        self: "Stream",
        exclude_event_types: list[str],
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Asynchronously generate events from the CrowdStrike Falcon Event Stream API.

        This method opens a stream to the Falcon API, iterates over the lines in the
        stream, and decodes and yields each event. It automatically refreshes the client
        token and reopens the stream if the token has expired.

        Parameters
        ----------
        exclude_event_types: list[str]
            A list of event types to be excluded from the stream.

        Yields
        ------
        dict[str, Any]
            A dictionary containing the event data from the Falcon API and a
            count of event types seen so far.

        Raises
        ------
        ValueError
            If client authentication fails during the token refresh process.

        """
        # Open the stream
        await self.open_stream()
        # Asynchronously iterate over the lines in the stream
        async for line in self.spigot.content:
            # Decode the line from bytes to a string and remove trailing whitespace
            decoded_line = line.decode().rstrip()
            if decoded_line:
                # Load the event as a JSON object
                json_event = json.loads(decoded_line)
                event_type = json_event["metadata"]["eventType"]
                self.offset = json_event["metadata"]["offset"]
                # If the event is valid, yield it
                if self.is_valid_event(event_type, exclude_event_types):
                    yield {"falcon": json_event}
            # If the token has expired, refresh it and reopen the stream
            if self.token_expired():
                refresh = await self.refresh()
                if refresh:
                    continue
                msg = "Failed to refresh token."
                raise ValueError(msg)

    def is_valid_event(
        self: "Stream",
        event_type: str,
        exclude_event_types: list[str],
    ) -> bool:
        """Check if a given event type is valid or not.

        Parameters
        ----------
        event_type: str
            The type of the event to be checked.
        exclude_event_types: list[str]
            A list of event types to be excluded.

        Returns
        -------
        bool
            Returns True if the event_type is not in the exclude_event_types list,
            otherwise returns False.

        """
        return event_type not in exclude_event_types


# pylint: disable=too-many-locals
async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:
    """Entrypoint for the eventstream event_source plugin.

    Parameters
    ----------
    queue: asyncio.Queue
        The queue to send events to
    args: dict[str, Any]
        The event_source arguments

    Raises
    ------
    ValueError
        If a argument is invalid

    """
    falcon_client_id: str = str(args.get("falcon_client_id"))
    falcon_client_secret: str = str(args.get("falcon_client_secret"))
    falcon_cloud: str = str(args.get("falcon_cloud", "us-1"))
    stream_name: str = str(args.get("stream_name", "eda")).lower()
    offset: Optional[int] = args.get("offset")
    latest: bool = bool(args.get("latest", False))
    delay: float = float(args.get("delay", 0))
    include_event_types: list[str] = list(args.get("include_event_types", []))
    exclude_event_types: list[str] = list(args.get("exclude_event_types", []))

    if falcon_cloud not in REGIONS:
        msg = f"Invalid falcon_cloud: {falcon_cloud}, must be one of {list(REGIONS.keys())}"
        raise ValueError(msg)

    # Offset and latest are mutually exclusive
    if offset and latest:
        msg = "'offset' and 'latest' are mutually exclusive parameters."
        raise ValueError(msg)

    falcon = AIOFalconAPI(
        client_id=falcon_client_id,
        client_secret=falcon_client_secret,
        base_url=REGIONS[falcon_cloud],
    )

    token = await falcon.authenticate()
    available_streams = await falcon.list_available_streams(token, stream_name)

    if not available_streams["resources"]:
        logger.info(
            "Unable to open stream, no streams available. Ensure you are using a unique stream_name.",
        )
        return

    streams: list[Stream] = [
        Stream(falcon, stream_name, offset, latest, include_event_types, stream)
        for stream in available_streams["resources"]
    ]

    try:
        # Iterate over each stream in the streams list
        for stream in streams:
            async for event in stream.stream_events(exclude_event_types):
                await queue.put(event)
                await asyncio.sleep(delay)
    except asyncio.TimeoutError:
        logger.exception("Timeout occurred while streaming events.")
    except aiohttp.ClientError:
        logger.exception("Client error occurred while streaming events.")
    except Exception:  # pylint: disable=broad-except
        logger.exception("Uncaught Plugin Task Error.")
    else:
        logger.info("All streams processed successfully.")
    finally:
        logger.info("Plugin Task Finished..cleaning up")
        # Close the stream and API session outside the loop
        for stream in streams:
            if stream.spigot:
                await stream.spigot.close()
        await falcon.close()


if __name__ == "__main__":

    class MockQueue:
        """Mock Queue for testing purposes."""

        async def put(self: "MockQueue", event: dict) -> None:
            """Print the event.

            Parameters
            ----------
            event: dict
                The event to be printed.

            """
            print(event)  # noqa: T201

    mock_arguments = {}
    asyncio.run(main(MockQueue(), mock_arguments))
