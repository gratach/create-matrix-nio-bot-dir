#!/usr/bin/env python3

"""
This is a modified version of the verify_with_emoji.py that was originaly
created in the matrix-nio repository and was adapted by wreald to fix
a bug of a missing key verification request event.

Original version:
https://github.com/matrix-nio/matrix-nio/blob/45af13b70cc60f4bf7be6cdfd5513b7730ec3108/examples/verify_with_emoji.py

Adapted version:
https://github.com/wreald/matrix-nio/blob/5cb8e99965bcb622101b1d6ad6fa86f5a9debb9a/examples/verify_with_emoji.py

Bug discussion:
https://github.com/matrix-nio/matrix-nio/issues/430

This version of the programm prepares a directory that contains a
matrix-nio store and a credentials file. It also supports a mechanism
to verify the device of the other party by accepting the emoji verification.
The created nio bot dir can be used as login credentials for a matrix bot.

To use this script the matrix-nio components for end to end encryption
must be installed (see https://github.com/matrix-nio/matrix-nio).
You must have created a Matrix account (for example on https://app.element.io/)
and have the username and password ready. You have to be logged in to your
account with an matrix client like Element (https://element.io/) or the browser
version of Element (https://app.element.io/).

Start the script and follow the instructions. The script will ask for the
device name of the bot. Choose a alphanumeric (can include _) name for the device
that is used to recognize the login credentials that you are going to create.
The created botdir will be called botdir_<device_name> and will be created in
the same directory as the script. The program will ask for the homeserver URL,
the user ID and the password of the account. Use the same credentials that you
use to log in to your account with the matrix client.

After the login was successful the program will wait for the other party to
initiate an emoji verification with the bot to verify the cryptographic keys
of the botdir. You now have to initiate the emoji verification with the bot
from the other client. In Element you can do this by selecting settings ->
all settings -> sessions -> selecting the session that can be identified by
the device name and then selecting "Verify". 

You will be asked to compare the emojis that are displayed on the bot and the 
other client. If the emojis match you can confirm the verification. Make sure
that you first confirm the verification on the other client before you confirm
the verification on the bot. After the verification was successful you can use
the botdir as login credentials for a matrix bot.

"""

import asyncio
import getpass
import json
import os
import sys
import traceback
from pathlib import Path
from random import randint

import aiofiles

from nio import (
    AsyncClient,
    AsyncClientConfig,
    KeyVerificationCancel,
    KeyVerificationEvent,
    KeyVerificationKey,
    KeyVerificationMac,
    KeyVerificationStart,
    LocalProtocolError,
    LoginResponse,
    ToDeviceError,
    ToDeviceMessage,
    UnknownToDeviceEvent,
)

ROOT_DIR = Path(__file__).parent.resolve()
bot_dir_names = []
for content in ROOT_DIR.iterdir():
    if content.name.startswith("botdir_"):
        bot_dir_names.append(content.name[7:])

default_bot_name = bot_dir_names[0] if bot_dir_names else 'bot' + str(randint(1000, 9999))
device_name = input(f"Choose a name for the bot device (default '{default_bot_name}'): ") or default_bot_name

# Path of the bot directory
BOT_DIR = Path(__file__).parent.resolve() / ("botdir_" + device_name)
# file to store credentials in case you want to run program multiple times
CONFIG_FILE = BOT_DIR / "login.json"
# directory to store persistent data for end-to-end encryption
STORE_PATH = BOT_DIR / "store"

if not BOT_DIR.exists():
    print("Creating bot directory at the path: ", str(BOT_DIR))
    BOT_DIR.mkdir()
else:
    print("Using the existing bot directory at the path: ", str(BOT_DIR))

if not (BOT_DIR / "README.md").exists():
    with open(BOT_DIR / "README.md", "w") as f:
        with open(ROOT_DIR / "botdirinfo.md", "r") as f2:
            f.write(f2.read())


class Callbacks:
    """Class to pass client to callback methods."""

    def __init__(self, client):
        """Store AsyncClient."""
        self.client = client

    async def to_device_callback(self, event):  # noqa
        """Handle events sent to device."""
        try:
            client = self.client

            if event.source['type'] == 'm.key.verification.request':
                """First step in new flow: receive a request proposing
                a set of verification methods, and in this case respond
                saying we only support SAS verification.
                """
                print(
                    "Got verification request. "
                    "Waiting for other device to accept SAS method..."
                )
                if 'm.sas.v1' not in event.source['content']['methods']:
                    print(
                        "Other device does not support SAS authentication. "
                        f"Methods: {event.source['content']['methods']}."
                    )
                    return
                assert client.device_id is not None
                assert client.user_id is not None
                txid = event.source['content']['transaction_id']
                ready_event = ToDeviceMessage(
                    type                = 'm.key.verification.ready',
                    recipient           = event.sender,
                    recipient_device    = event.source['content']['from_device'],
                    content             = {
                        'from_device': client.device_id,
                        'methods': ['m.sas.v1'],
                        'transaction_id': txid,
                    },
                )
                resp = await client.to_device(ready_event, txid)
                if isinstance(resp, ToDeviceError):
                    print(f"to_device failed with {resp}")
            elif isinstance(event, KeyVerificationStart):  # first step
                """first step: receive KeyVerificationStart
                KeyVerificationStart(
                    source={'content':
                            {'method': 'm.sas.v1',
                             'from_device': 'DEVICEIDXY',
                             'key_agreement_protocols':
                                ['curve25519-hkdf-sha256', 'curve25519'],
                             'hashes': ['sha256'],
                             'message_authentication_codes':
                                ['hkdf-hmac-sha256', 'hmac-sha256'],
                             'short_authentication_string':
                                ['decimal', 'emoji'],
                             'transaction_id': 'SomeTxId'
                             },
                            'type': 'm.key.verification.start',
                            'sender': '@user2:example.org'
                            },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    from_device='DEVICEIDXY',
                    method='m.sas.v1',
                    key_agreement_protocols=[
                        'curve25519-hkdf-sha256', 'curve25519'],
                    hashes=['sha256'],
                    message_authentication_codes=[
                        'hkdf-hmac-sha256', 'hmac-sha256'],
                    short_authentication_string=['decimal', 'emoji'])
                """

                if "emoji" not in event.short_authentication_string:
                    print(
                        "Other device does not support emoji verification "
                        f"{event.short_authentication_string}."
                    )
                    return
                resp = await client.accept_key_verification(event.transaction_id)
                if isinstance(resp, ToDeviceError):
                    print(f"accept_key_verification failed with {resp}")

                sas = client.key_verifications[event.transaction_id]

                todevice_msg = sas.share_key()
                resp = await client.to_device(todevice_msg)
                if isinstance(resp, ToDeviceError):
                    print(f"to_device failed with {resp}")

            elif isinstance(event, KeyVerificationCancel):  # anytime
                """at any time: receive KeyVerificationCancel
                KeyVerificationCancel(source={
                    'content': {'code': 'm.mismatched_sas',
                                'reason': 'Mismatched authentication string',
                                'transaction_id': 'SomeTxId'},
                    'type': 'm.key.verification.cancel',
                    'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    code='m.mismatched_sas',
                    reason='Mismatched short authentication string')
                """

                # There is no need to issue a
                # client.cancel_key_verification(tx_id, reject=False)
                # here. The SAS flow is already cancelled.
                # We only need to inform the user.
                print(
                    f"Verification has been cancelled by {event.sender} "
                    f'for reason "{event.reason}".'
                )

            elif isinstance(event, KeyVerificationKey):  # second step
                """Second step is to receive KeyVerificationKey
                KeyVerificationKey(
                    source={'content': {
                            'key': 'SomeCryptoKey',
                            'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.key',
                        'sender': '@user2:example.org'
                    },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    key='SomeCryptoKey')
                """
                sas = client.key_verifications[event.transaction_id]

                print(f"{sas.get_emoji()}")

                yn = input("Do the emojis match? (Y/N) (C for Cancel) - verify them on the other device first:")
                if yn.lower() == "y":
                    print(
                        "Match! The verification for this " "device will be accepted."
                    )
                    resp = await client.confirm_short_auth_string(event.transaction_id)
                    if isinstance(resp, ToDeviceError):
                        print(f"confirm_short_auth_string failed with {resp}")

                    # Extra step in new flow: once we have completed the SAS
                    # verification successfully, send a 'done' to-device event
                    # to the other device to assert that the verification was
                    # successful.
                    done_message = ToDeviceMessage(
                        type                = 'm.key.verification.done',
                        recipient           = event.sender,
                        recipient_device    = sas.other_olm_device.device_id,
                        content             = {
                            'transaction_id': sas.transaction_id,
                        },
                    )
                    resp = await client.to_device(done_message, sas.transaction_id)
                    if isinstance(resp, ToDeviceError):
                        client.log.error(f"'done' failed with {resp}")

                elif yn.lower() == "n":  # no, don't match, reject
                    print(
                        "No match! Device will NOT be verified "
                        "by rejecting verification."
                    )
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=True
                    )
                    if isinstance(resp, ToDeviceError):
                        print(f"cancel_key_verification failed with {resp}")
                else:  # C or anything for cancel
                    print("Cancelled by user! Verification will be " "cancelled.")
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=False
                    )
                    if isinstance(resp, ToDeviceError):
                        print(f"cancel_key_verification failed with {resp}")

            elif isinstance(event, KeyVerificationMac):  # third step
                """Third step is to receive KeyVerificationMac
                KeyVerificationMac(
                    source={'content': {
                        'mac': {'ed25519:DEVICEIDXY': 'SomeKey1',
                                'ed25519:SomeKey2': 'SomeKey3'},
                        'keys': 'SomeCryptoKey4',
                        'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.mac',
                        'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    mac={'ed25519:DEVICEIDXY': 'SomeKey1',
                         'ed25519:SomeKey2': 'SomeKey3'},
                    keys='SomeCryptoKey4')
                """
                sas = client.key_verifications[event.transaction_id]
                try:
                    todevice_msg = sas.get_mac()
                except LocalProtocolError as e:
                    # e.g. it might have been cancelled by ourselves
                    print(
                        f"Cancelled or protocol error: Reason: {e}.\n"
                        f"Verification with {event.sender} not concluded. "
                        "Try again?"
                    )
                else:
                    resp = await client.to_device(todevice_msg)
                    if isinstance(resp, ToDeviceError):
                        print(f"to_device failed with {resp}")
            elif event.source['type'] == 'm.key.verification.done':
                # Final step, other device acknowledges verification success.
                txid = event.source['content']['transaction_id']
                sas = client.key_verifications[txid]

                print(
                    f"sas.we_started_it = {sas.we_started_it}\n"
                    f"sas.sas_accepted = {sas.sas_accepted}\n"
                    f"sas.canceled = {sas.canceled}\n"
                    f"sas.timed_out = {sas.timed_out}\n"
                    f"sas.verified = {sas.verified}\n"
                    f"sas.verified_devices = {sas.verified_devices}\n"
                )
                print(
                    "Emoji verification was successful!\n"
                    "Hit Control-C to stop the program or "
                    "initiate another Emoji verification from "
                    "another device or room."
                )
            else:
                print(
                    f"Received unexpected event type {type(event)}. "
                    f"Event is {event}. Event will be ignored."
                )
        except BaseException:
            print(traceback.format_exc())


def write_details_to_disk(resp: LoginResponse, homeserver, device_name) -> None:
    """Write the required login details to disk.

    It will allow following logins to be made without password.

    Arguments:
    ---------
        resp : LoginResponse - successful client login response
        homeserver : str - URL of homeserver, e.g. "https://matrix.example.org"

    """
    # open the config file in write-mode
    with open(str(CONFIG_FILE), "w") as f:
        # write the login details to disk
        json.dump(
            {
                "homeserver": homeserver,  # e.g. "https://matrix.example.org"
                "user_id": resp.user_id,  # e.g. "@user:example.org"
                "device_id": resp.device_id,  # device ID, 10 uppercase letters
                "access_token": resp.access_token,  # cryptogr. access token
                "device_name": device_name,  # e.g. "matrix-nio"
            },
            f,
        )


async def login() -> AsyncClient:
    """Handle login with or without stored credentials."""
    # Configuration options for the AsyncClient
    client_config = AsyncClientConfig(
        max_limit_exceeded=0,
        max_timeouts=0,
        store_sync_tokens=True,
        encryption_enabled=True,
    )

    # If there are no previously-saved credentials, we'll use the password
    if not CONFIG_FILE.exists():
        print(
            "First time use. Did not find credential file. Asking for "
            "homeserver, user, and password to create credential file."
        )
        homeserver = "https://matrix.example.org"
        homeserver = input(f"Enter your homeserver URL: [{homeserver}] ")

        if not (homeserver.startswith("https://") or homeserver.startswith("http://")):
            homeserver = "https://" + homeserver

        user_id = "@user:example.org"
        user_id = input(f"Enter your full user ID: [{user_id}] ")

        if not STORE_PATH.exists():
            STORE_PATH.mkdir()

        # Initialize the matrix client
        client = AsyncClient(
            homeserver,
            user_id,
            store_path=str(STORE_PATH),
            config=client_config,
        )
        pw = getpass.getpass()

        resp = await client.login(password=pw, device_name=device_name)

        # check that we logged in successfully
        if isinstance(resp, LoginResponse):
            write_details_to_disk(resp, homeserver, device_name)
        else:
            print(f'homeserver = "{homeserver}"; user = "{user_id}"')
            print(f"Failed to log in: {resp}")
            sys.exit(1)

        print(
            "Logged in using a password. Credentials were stored. "
            "On next execution the stored login credentials will be used."
        )

    # Otherwise the config file exists, so we'll use the stored credentials
    else:
        # open the file in read-only mode
        async with aiofiles.open(str(CONFIG_FILE), "r") as f:
            contents = await f.read()
        config = json.loads(contents)
        # Initialize the matrix client based on credentials from file
        client = AsyncClient(
            config["homeserver"],
            config["user_id"],
            device_id=config["device_id"],
            store_path=STORE_PATH,
            config=client_config,
        )

        client.restore_login(
            user_id=config["user_id"],
            device_id=config["device_id"],
            access_token=config["access_token"],
        )
        print("Logged in using stored credentials.")

    return client


async def main() -> None:
    """Login and wait for and perform emoji verify."""
    client = await login()
    # Set up event callbacks
    callbacks = Callbacks(client)
    client.add_to_device_callback(callbacks.to_device_callback, (KeyVerificationEvent, UnknownToDeviceEvent))
    # Sync encryption keys with the server
    # Required for participating in encrypted rooms
    if client.should_upload_keys:
        await client.keys_upload()
    print(
        "This program is ready and waiting for the other party to initiate "
        'an emoji verification with us by selecting "Verify by Emoji" '
        "in their Matrix client."
    )
    await client.sync_forever(timeout=30000, full_state=True)


try:
    asyncio.run(main())
except Exception:
    print(traceback.format_exc())
    sys.exit(1)
except KeyboardInterrupt:
    print("Received keyboard interrupt.")
    sys.exit(0)