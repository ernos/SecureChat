import asyncio
import sys
import os
from pathlib import Path
from client import ChatClient

# Test user data (from testusers.json)
test_users = [
# Full test user data (from testusers.json)
    {"username": "ernos", "password": "<random_word>", "friends": ["pebnop", "johndoe", "alice"]},
    {"username": "pebnop", "password": "<random_word>", "friends": ["ernos", "johndoe", "alice"]},
    {"username": "johndoe", "password": "<random_word>", "friends": ["alice", "pebnop", "grace"]},
    {"username": "alice", "password": "<random_word>", "friends": ["pebnop", "johndoe", "ernos", "bob"]},
    {"username": "bob", "password": "<random_word>", "friends": ["alice", "johndoe", "ernos", "frank"]},
    {"username": "charlie", "password": "<random_word>", "friends": ["pebnop", "johndoe", "ernos"]},
    {"username": "dave", "password": "<random_word>", "friends": ["pebnop", "johndoe", "ernos"]},
    {"username": "eve", "password": "<random_word>", "friends": []},
    {"username": "frank", "password": "<random_word>", "friends": ["bob"]},
    {"username": "grace", "password": "<random_word>", "friends": []}
]



async def register_and_add_friends(user):
    client = ChatClient()
    print(f"[TEST] Connecting and registering user: {user['username']}")

    # register_or_login is called by connect()
    for friend in user["friends"]:
    
        print(f"[TEST] User {user['username']} connected successfully.")
        client.username = user["username"]
        client.password = user["password"]
        await client.connect(listen=False)
        if(client.isConnectedToServer):  
            for friend in user["friends"]:
                if friend:
                    print(f"[TEST] Sending friend request from {user['username']} to {friend}")
                    await client.send_friend_request(friend)
                else:
                    print(f"[TEST] User {user['username']} not connected, cannot send friend request to {friend}")
                    
        await asyncio.sleep(0.5)  # Give server time to process
    await client.disconnect()
    print(f"[TEST] Done with user: {user['username']}")



async def main():
    for user in test_users:
        await register_and_add_friends(user)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[TEST] Test interrupted by user.")
    except Exception as e:
        print(f"[TEST] Fatal error: {e}")

