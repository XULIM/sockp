# Socket Programming: Discord Replacement

Discord launches a new update every 10 mins and is very annoying.

Plus discord is packing a lot more bloatware into it to make it very slow.

Just want something light weight that can send and receive messages, upload
files, screen share, and stream.


## Plan

**Client-Server model:**
- Client connects to the server and sends a message.
- Server receives the message and relays the message to the recipient.
- Recipient (also a client) receives the message and displays it on their end.

**Database:**
- Might need a database to store user data.

**Authentification:**
- Probably need user authentification.

## Agenda:
- [x] Code up the server.
    - [x] accept and recv
- [x] Code up the client.
    - [x] connect and send
- [x] Make sure they can communicate.
- [ ] Code up the server with pthreads.
- [ ] Make sure the server can handle multiple connections.
- [ ] Make sure they can communicate.
- [ ] Data serialization?
- [ ] Add DB if needed.
- [ ] Code up a GUI for client.
- [ ] VER 1.0
- [ ] Add ability to send files.
- [ ] Add voice chat.
- [ ] Add OAuth if needed.

## Bug Fixes
- [ ] Handle usernames with a length longer than USERNAME_LEN
- [ ] Handle messages with a length longer than BUFLEN
- [ ] Handle usernames on the client side on first join and just have the server
  listen until there is a valid username instead of sending the username prompt
  from the server.

## Update Log

2025-03-17 --

Finished the pollserver, now it can have multiple clients connecting to the
server and when one client sends a message, the message is broadcasted to all
other connected clients.

2025-04-03 --

Server and client both done. Client also uses poll to handle I/O. Maybe it is
time for user authentification and maybe making a database for the users.
- Username?
- User authentification with OTP or sign up via email?

Maybe I should consider finishing the base functionalities of the server first
(i.e. processing files and voice messages, do people even use voice messages?)


2025-05-07 --

Now accepts the username on client side, the server only receives.

Need to be able to identify who sent the message, so adding the username in
front of the message would be good.

Then maybe code up an UI first then add DB and Auth?

2025-05-10 --

Voice chat with datagram socket.

Data serialization needed.
