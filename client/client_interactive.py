import sys
import asyncio
from client import ChatClient, SERVER_CERT_FILE

async def main():
    # Support username/password as command-line arguments
    username = None
    password = None

    if len(sys.argv) > 1:
        username = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]

    client = ChatClient()
    if username:
        client.username = username
    if password:
        client.password = password

    print(f"[CONFIG] Using username: {client.username} (from {'args' if username else 'data/client_config.json'})")
    print(f"Connecting to {client.server_uri} as {client.username}...")
    await client.connect(listen=False)

    await client.get_friends_list()

    from client import interactive_shell
    await asyncio.gather(
        client.listen_for_messages(),
        interactive_shell(client)
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Client shutting down...")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
