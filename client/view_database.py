#!/usr/bin/env python3
"""
Database viewer for the Secure Chat Server
Shows users, messages, and statistics
"""

import asyncio
import aiosqlite
import sys
from database_manager import DatabaseManager

async def view_database():
    """View the contents of the chat server database"""
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    print("🗄️  Chat Server Database Contents")
    print("=" * 50)
    
    # View users
    print("\n👥 REGISTERED USERS:")
    cursor = await db_manager.db.execute("""
        SELECT id, username, created_at, last_login, total_messages_received, 
               unread_messages, auto_delete_hours, is_active
        FROM users ORDER BY created_at DESC
    """)
    users = await cursor.fetchall()
    
    if users:
        print(f"{'ID':<4} {'Username':<15} {'Created':<12} {'Last Login':<12} {'Msgs':<6} {'Unread':<8} {'Auto-Del':<8} {'Active'}")
        print("-" * 80)
        for user in users:
            created_time = f"{user[2]:.0f}" if user[2] else "Never"
            last_login = f"{user[3]:.0f}" if user[3] else "Never"
            print(f"{user[0]:<4} {user[1]:<15} {created_time:<12} {last_login:<12} {user[4]:<6} {user[5]:<8} {user[6]:<8} {user[7]}")
    else:
        print("No users found.")
    
    # View messages
    print("\n📨 MESSAGES:")
    cursor = await db_manager.db.execute("""
        SELECT m.id, u1.username as sender, u2.username as recipient, 
               m.room_name, m.message_type, m.created_at, m.read_at, 
               m.expires_at, m.is_deleted, LENGTH(m.content) as content_length
        FROM messages m
        LEFT JOIN users u1 ON m.sender_id = u1.id
        LEFT JOIN users u2 ON m.recipient_id = u2.id
        ORDER BY m.created_at DESC
        LIMIT 10
    """)
    messages = await cursor.fetchall()
    
    if messages:
        print(f"{'ID':<4} {'Sender':<12} {'Recipient':<12} {'Room':<8} {'Type':<8} {'Created':<12} {'Read':<8} {'Expires':<12} {'Del':<4} {'Len'}")
        print("-" * 100)
        for msg in messages:
            created_time = f"{msg[5]:.0f}" if msg[5] else "Never"
            read_time = f"{msg[6]:.0f}" if msg[6] else "Unread"
            expires_time = f"{msg[7]:.0f}" if msg[7] else "Never"
            recipient = msg[2] if msg[2] else "Public"
            room = msg[3] if msg[3] else "N/A"
            print(f"{msg[0]:<4} {msg[1]:<12} {recipient:<12} {room:<8} {msg[4]:<8} {created_time:<12} {read_time:<8} {expires_time:<12} {msg[8]:<4} {msg[9]}")
    else:
        print("No messages found.")
    
    # Database statistics
    print("\n📊 DATABASE STATISTICS:")
    
    # Count users
    cursor = await db_manager.db.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
    active_users = (await cursor.fetchone())[0]
    
    # Count messages
    cursor = await db_manager.db.execute("SELECT COUNT(*) FROM messages WHERE is_deleted = FALSE")
    active_messages = (await cursor.fetchone())[0]
    
    # Count unread messages
    cursor = await db_manager.db.execute("SELECT COUNT(*) FROM messages WHERE read_at IS NULL AND is_deleted = FALSE")
    unread_messages = (await cursor.fetchone())[0]
    
    print(f"Active users: {active_users}")
    print(f"Active messages: {active_messages}")
    print(f"Unread messages: {unread_messages}")
    
    await db_manager.close()

async def debug_all_tables():
    """Show all table contents using the debug function"""
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    print("🔍 DEBUG MODE: All Table Contents")
    print("=" * 50)
    
    # Use the debug functions
    await db_manager.debug_table_summary()
    await db_manager.debug_print_all_tables()
    
    await db_manager.close()

def show_usage():
    """Show usage information"""
    print("Usage:")
    print("  python view_database.py [option]")
    print()
    print("Options:")
    print("  (no option)  - Show formatted view of users and messages")
    print("  --debug      - Show all tables with all columns and rows")
    print("  --summary    - Show table summary only")
    print("  --help       - Show this help message")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        option = sys.argv[1]
        if option == "--debug":
            asyncio.run(debug_all_tables())
        elif option == "--summary":
            async def summary_only():
                db_manager = DatabaseManager()
                await db_manager.initialize()
                await db_manager.debug_table_summary()
                await db_manager.close()
            asyncio.run(summary_only())
        elif option == "--help":
            show_usage()
        else:
            print(f"Unknown option: {option}")
            show_usage()
    else:
        asyncio.run(view_database())
