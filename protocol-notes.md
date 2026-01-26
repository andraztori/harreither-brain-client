

# Harreither Brain Protocol

## Overview

The protocol used is not classical IoT data sync, but rather a protocol
initially used for communicating with a client display device, where part of the
business logic is done on the serving device and some on the client display device.

For example, there might be a list of available states of some setting, but it
is not editable. Editing happens in a "random" screen that is not easily
connected to the actual multivalue state variable whose state changes are
automatically pushed to us.

The editing screen is then simply a set of UI buttons, and when one presses
them it is on-device logic that does the state change.

## Connection & Security

### Connection Establishment Flow

The connection is established through the following steps:

1. **CONNECTION_START (type_int: 10)** - Device initiates connection with device metadata
   - Client receives: `device_id`, `device_version`, `connection_id`

2. **CONNECTION_CONFIRM (type_int: 11)** - Client confirms and provides client info
   - Payload includes: `client_type`, `client_id`, `client_version`, `connection_id`

3. **CONNECTION_ESTABLISHED (type_int: 12)** - Device confirms successful connection

4. **SC_INIT (type_int: 14)** - Client initiates secure connection negotiation

5. **SC_PUBKEY (type_int: 15)** - Device sends its RSA public key and device signature

6. **SC_SECRET (type_int: 16)** - Client sends encrypted session key and IV
   - Encryption: RSA PKCS1v15
   - Session key: 32 bytes (AES-256)
   - Session IV: 16 bytes
   - Format: `{session_key_hex}:::{session_iv_hex}` encrypted with RSA

7. **SC_ESTABLISHED (type_int: 17)** - Device confirms secure connection, provides `sc_id`

### Encryption

After secure connection is established:
- **Algorithm**: AES-256 in CBC mode
- **Message format**: JSON → UTF-8 → encrypt → Base64 encode → send with `\x04` terminator
- **Padding**: PKCS7 padding with null bytes

## Message Structure

All messages (after secure connection) follow this JSON structure:
```json
{
  "type_int": <int>,
  "mc": <message_counter>,
  "payload": {...},
  "ref": <reference_id>
}
```

- `type_int`: Message type identifier
- `mc`: Message counter (auto-incrementing, 20000-32000 range)
- `payload`: Optional message-specific data
- `ref`: Optional reference ID for ACK/NACK responses

## Message Types

### Connection & Control
- **ACK (1)**: Acknowledgment of received message
- **NACK (0)**: Negative acknowledgment
- **HEARTBEAT (2)**: Keep-alive message
- **WAIT4ACK (3)**: Device indicates it's still processing

### Authentication
- **AUTH_LOGIN (30)**: Client sends username/password
- **AUTH_LOGIN_SUCCESS (32)**: Server confirms authentication
- **AUTH_LOGIN_DENIED (31)**: Server rejects credentials
- **AUTH_APPLY_TOKEN (33)**: Apply authentication token
- **AUTH_APPLY_TOKEN_RESPONSE (34)**: Token application response

### UI & Navigation
- **ACTUAL_SCREEN (200)**: Navigate to a specific screen by ID
  - Payload: `{"screenID": <id>, "objID": <optional_id>}`
- **ACTION_SELECTED (201)**: Select/press a button/action item
  - Payload: `{"VID": <vid>, "detail": <detail>, "objID": <optional_id>}`

### Data Updates (Device → Client)
- **SET_HOME_DATA (301)**: Device sends home/location information
- **ADD_SCREEN (296)**: Device defines a new screen
  - Structure: `screenID`, `title`, `statuspage`, `itemCount`, `objID`, `iconID`
- **ADD_DBENTRIES (297)**: Device sends database entry definitions
  - VID: Unique identifier
  - type: Data type (1 = button, 23 = readonly, 4 = settable, etc.)
  - text, min, max, step, unit, elements, pwd fields
- **ADD_ITEMS (299)**: Device adds UI items to a screen
  - Items contain: VID, detail, name, value, validity, objID, citems (child items)
- **UPDATE_ITEMS (300)**: Device updates item values
- **SET_ALERTS (302)**: Device sends alert messages

## Entity Structure

### Entry (Item)

Each entry has a 3-tuple key:
```
(VID, detail, objID)
```

- **VID** (Value ID): Identifier for the data item
- **detail**: Qualifier that determines behavior
  - `detail = 0`: "Go back" navigation button (skip in exploration)
  - `detail = 1`: Action button (skip in exploration)
  - Other values: Submenu/screen navigation id that can be directly treated as screenID
- **objID**: Optional object qualifier (screens can be identified by screenID+objID)

### Type Codes (from DBentry)

- **type = 1**: Button entry meant to be rendered (navigates to screen specified by detail/objID)
- **type = 4**: Settable value
- **type = 23**: Read-only value
- Other types handle various UI elements

## Menu Tree Discovery

When connecting, the library traverses the entire menu tree:

1. Start at initial screens received from device
2. When a type 1 entry (button) is encountered:
   - Send **ACTUAL_SCREEN** with the detail value as screenID
   - Then send **ACTION_SELECTED** to simulate pressing the button
3. Skip entries where:
   - `detail = 0` (go back)
   - `detail = 1` (pure action, no menu behind it - we don't want to press these as they have side effects)
4. The device will respond with **ADD_SCREEN** and **ADD_ITEMS** containing new menu items
5. Process recursively through all reachable menus


## Initial Data Exchange & Push Updates

After successful authentication, the device enters an initialization phase:

### Phase 1: Initial Data Transmission

The device sends descriptions of the first-level entities and screens:
- **ADD_SCREEN**: Definitions of all top-level screens available to the user
- **ADD_DBENTRIES**: Database entries describing all available data items (VIDs)
- **ADD_ITEMS**: Initial menu items and UI elements for the first level screens

The client should **ACK all messages** to confirm receipt.

### Phase 2: Initialization Complete

The device sends:
- **SET_HOME_DATA**: Home/location information
- **SET_ALERTS**: Any active alerts

Once **SET_ALERTS** is received, the client can consider initialization complete and is ready to:
- Navigate screens with ACTUAL_SCREEN (200)
- Interact with items via ACTION_SELECTED (201)
- Begin menu tree discovery

### Phase 3: Push Updates

After initialization, the device continuously sends:
- **UPDATE_ITEMS**: Value changes and state updates for existing items
- **SET_ALERTS**: New or updated alerts
- Any other data changes initiated on the device or by other connected clients

The client should maintain connections and process these push updates in real-time using registered update callbacks.

## Protocol Notes


### Navigation Rules

When an object has type 1, this means that the button is meant to be rendered. That button navigates to a screen in this way:
- New screen is identified by "detail" and optionally "objID" (screens are (screenID, objID) pairs)
- if detail is 0, it means go back and if detail is 1, it means an action will happen and button wont lead to a new screen

### Action Behavior

"Pushing" various buttons by taking ACTION_SELECTED (201) does not have any effect unless we have previously navigated to that screen with ACTUAL_SCREEN (200). It does not return error, but just silently breaks.

### Keep-Alive

The client periodically sends ACTION_SELECTED with `ScreenID: 100` as a keep-alive mechanism (every 270 seconds).

### Callbacks & Updates

All data updates (ADD_ITEMS, UPDATE_ITEMS, SET_ALERTS, etc.) trigger immediate asynchronous callbacks to registered update handlers. The application can process these updates in real-time without polling.
