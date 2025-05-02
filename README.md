# Videofied

This is an implementation of the Videofied alarm system protocol for Wirego (https://github.com/quarkslab/wirego/)

Credits to https://github.com/Mickaelh51/rsi-alarm-gateway for the protocol reverse.


## Protocol


| Link             |  Command     | Arguments             | Description                                                                       |
| --------------- | ------------- | --------------------- | --------------------------------------------------------------------------------- |
| Server->Client  | IDENT         | (1000)                | Server requests identification from client                                        |
| Client->Server  | IDENT         | (Serial number, 2)    | Client replies with serial number                                                |
| Server->Client  | SETKEY        | (KEY)                 | Server sends AES key                                                              |
| Server->Client  | VERSION       | (2, 0)                | Server sends its version                                                          |
| Server->Client  | AUTH1         | (AUTH1, S_CHAL)       | Server sends a challenge: S_CHAL                                                  |
| Client->Server  | AUTH2         | (XXX, C_CHAL)         | Client challenge response: XXX = AES(S_CHAL, KEY), C_CHAL is the client challenge |
| Server->Client  | AUTH3         | (YYY)                 | Server challenge response: YYY = AES(C_CHAL, KEY)                                 |
| Client->Server  | AUTH_SUCCESS  | (a,b,c,d,e,f,g,h,i,j) | Client declares success with 10 args (a is the configurable "client number", c is the local date)                                      |
| Client->Server  | EVENT         | (A,B,C)               | Client sends an event: A is the event number, B is the event source, C is unknown |
| Client->Server  | REQACK        | (D)                   | Client sends an ack request                                                       |
| Server->Client  | ACK           | ()                    | Server sends an ack                                                               |

__Notes:__ 

The SETKEY packet might be skipped if the device has been recently connected to the server (the last key is reused).

During the IDENT response, if the second argument is set to 1 we skip the VERSION packet

The challenge/responses seems to be checked at the very end of the auth section, once AUTH3 has been sent. Upon failure (wrong aes key), session is closed without notice.

If opening a new connection to the server while another one is active, all connections are closed after the client IDENT.

There's no keepalive, after 3 minutes the server closes the connection.

Auth succeed examples:

  - AUTH_SUCCESS,52683,2,20150101174144,5,2,E6612124110,0,XLP081300,0,27FF
  - AUTH_SUCCESS,0000,0,20250502084234,5,2,E6612124110,0,XLP081300,0,27FF