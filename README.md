# Harreither Brain Client

Async Python client and CLI for talking to Harreither Brain websocket devices. It establishes the secure channel, authenticates with the device, and streams messages back and forth.

## Installation

```bash
pip install harreither-brain-client
```

Or from source:

```bash
pip install .
```

## CLI usage

```bash
harreither-brain \
  --host ws://device-host:8080 \
  --username YOUR_USERNAME \
  --password YOUR_PASSWORD \
  [--proxy] [--strict] [-v]
```

- `--proxy` routes through http://localhost:8080.
- `--strict` fails if the device sends unexpected fields to us.
- `-v` enables debug logging.

## Library usage

```python
import asyncio
from harreither_brain_client import Connection

async def main():
    conn = Connection(strict_mode=False)
    await conn.async_websocket_connect("ws://device-host:8080")
    await conn.establish_secure_connection()
    await conn.enqueue_authentication_flow(
        username="user",
        password="pass",
        auto_start_session=True,
    )
    await conn.messages_process()

asyncio.run(main())
```

## Development

- Run tests: `python -m unittest discover tests`
- Build artifacts: `python -m build`
- Check metadata: `python -m twine check dist/*`

## License

MIT
