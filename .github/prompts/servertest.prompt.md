---
mode: ask
---
# Server Feature Test Checklist & Error Identification Prompt

## Task
The server is already running.
You are to create a few different users by simply connecting a client in a terminal with commands --username <username> and --password <password>
and then calling the register_user function in (`client/client.py`)
Friends will work like this:
* It blocks clients from sending messages to anyone who is not their friend. 
  Create all users in (`.github/prompts/testusers.json`) in the server database(`server/data/server.db`) one by one by connecting to the server.
    - Client Database:
      The friendship will be added to friends table only if both clients has sent/answered a friend request
    - Server Database: 
      Same thing here, only if both clients have sent/answered a friend request.

## Instructions
**1. Update client_testusers.py**

**2. Connect to the server by calling client.connect()**
    it will automatically connect and call register_or_login()

    if you are successful in registering the user you will get: 
    message_type == "registration_success" and the server will send:
    {"message": "User registered successfully", "username": "<username>"}
3. Only if successful in registering the user, you can then proceed to add friends by calling the add_friend function. For all of the users friends in that users.friends list
**4 if successful, you should** receive a message from the server confirming the friendship addition.
**5. Disconnect the client from the server, and repeat the steps and connect the next user**

## Example Output

### Test Checklist
- [ ] User registration: New users can register with unique usernames and valid credentials.
- [ ] User login: Registered users can log in with correct credentials; invalid credentials are rejected.
- [ ] Public message delivery: Messages sent to a room are received by all room members.
- [ ] Private messaging: Users can send and receive encrypted private messages.
- [ ] Error handling: Malformed requests return structured error responses.
- [ ] Session management: Sessions are created and expired correctly.
- [ ] Encryption: All payloads are encrypted and decrypted as expected.

### Error Identification

- For each failed test, note the observed behavior and compare it to the expected result.
- Check server logs in `logs/server.log` for error messages or stack traces.
- Record the exact error message, timestamp, and any relevant request/response data.
- Use structured error codes and messages as defined in the protocol documentation.
- If possible, attach screenshots or log excerpts to your bug report.

---

**Success Criteria:**  
A complete, actionable checklist covering all major server features, with clear error identification steps for each test.