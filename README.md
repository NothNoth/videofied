# Videofied

This is an implementation of the Videofied alarm system protocol for Wirego (https://github.com/quarkslab/wirego/)

Credits to https://github.com/Mickaelh51/rsi-alarm-gateway for the protocol reverse.


## Protocol


| Link             |  Command     | Arguments             | Description                                                                       |
| --------------- | ------------- | --------------------- | --------------------------------------------------------------------------------- |
| Server->Client  | IDENT         | (1000)                | Server requests identification from client                                        |
| Client->Server  | IDENT         | (Serial number, 2)    | Client resplies with serial number                                                |
| Server->Client  | SETKEY        | (KEY)                 | Server sends AES key                                                              |
| Server->Client  | VERSION       | (2, 0)                | Server sends its version                                                          |
| Server->Client  | AUTH1         | (AUTH1, S_CHAL)       | Server sends a challenge: S_CHAL                                                  |
| Client->Server  | AUTH2         | (XXX, C_CHAL)         | Client challenge response: XXX = AES(S_CHAL, KEY), C_CHAL is the client challenge |
| Server->Client  | AUTH3         | (YYY)                 | Server challenge response: YYY = AES(C_CHAL, KEY)                                 |
| Client->Server  | AUTH_SUCCESS  | (a,b,c,d,e,f,g,h,i,j) | Client declares success with 10 unknown args                                      |
| Client->Server  | EVENT         | (A,B,C)               | Client sends an event: A is the event number, B is the event source, C is unknown |
| Client->Server  | REQACK        | (D)                   | Client sends an ack request                                                       |
| Server->Client  | ACK           | ()                    | Server sends an ack                                                               |

