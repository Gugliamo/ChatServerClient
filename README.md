# ChatServerClient
A project written in C including a multi-user chat server and client.

The chat server and client were written completey in C in a linux CLI environment.
The server uses a TCP connection and supports 20 concurrent users. Four commands are supported, including login, logout, list and private.
Login command is able to change the name of the current user in the user list with the name specified (ex. login DifferentUsername).
Logout command disconnects a client from the server and turns off the program.
List will list all current users on the server.
Private allows for private messages to a specific user (ex. private DifferentUsername hello there =] ).

Although there is a supplied client program, telnet connection to the server is supported for demonstration purposes. 
Semaphores are used throughout the server program as this is a multi-client, multi-threaded program.



Further side-notes and testing:
I tried to implement a function (threadCheck()) that checks for unused threads to reclaim them with pthread_join. I placed the call to this function in the beginning of my main accept loop to check over available threads and if they are still being used with a combination of status flags and pthread_kill checks. It seems to work the majority of the time, but once in a while something triggers a bug and my program quits. I wanted to implement this function to continuously run in the program to reclaim unused threads as soon as a user leaves, but I already spent too much time on this extra function. = P

I added a few extra members to the structure which keeps track of users in my program. The extra members are fd, threadID and status. fd holds the file descriptor the program uses to communicate with the user, and threadID holds the thread ID the user is running on in the program. Both of these members are used in my function to keep track of who is who when I’m passing information between various functions. Finally, I added status as a member to my struct in an attempt to keep track of the thread status for each of the user’s threads. The plan was to have the status as 0 when the user’s thread is not initialiazed, 1 when the thread is in use, and 2 for when the thread is ready to be recycled using pthread_join(). 

Because my program relies on a structure which is set to be a size of 20, I planned to implement a function which would check through the indexes and determine if an earlier index has been cleared and available for future use. The function would set my counter - which keep tracks of which structure index I’m currently assigning - to an earlier index which may be free. I had a few bugs with it and decided to comment it out of my program as I ran out of time. I wanted this to work so the server could truly hold 20 users at any one time, but unfortunately my program is now limited to a total of 20 consecutive user connections.

For testing, I ran the server program from apollo and connected from munro, humber and using telnet from apollo. I changed everyone’s names, including one multi-word name. I then used list in all the clients, then followed it with private messages to a couple clients and one to themselves. Then, I just sent some messages to everyone. Finally, I logged out. Testing seemed to work well.
