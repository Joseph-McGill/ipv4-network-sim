## IPv4 Network Simulator

This repository simulates a network in C using sockets. It is currently
configured for the following 12 node network architecture:

![Network architecture](http://i.imgur.com/JwWiUPD.png)

Each node in the architecture is configured by the corresponding .txt file in
the [hosts](../master/hosts/) directory. Each host has a fake IP address, port number, number of
neighbors, and neighbor information.

The routing table for each node is built using the Distance Vector routing
protocol. Each node sends its routing table information to its neighbors.
After information is received, the nodes routing table is updated with the
received information until no more messages are being sent. Afterwards, each
node sends the frams to the proper nodes based on the routing table.

### Viewing the frames
The frames can be viewed using the supplied [frame_reader.c](../master/frame_reader.c)
file which can be compiled and ran with

    gcc frame_reader.c
    ./a.out input_data.bin

### Compiling the program
The program utilizes threads for sending and receiving frames, and must be
compiled using the pthread library with

    gcc network_sim.c -pthread

### Running the program
The program can be easily ran with the supplied [run](../master/run) shell script.
The script launches 12 x-term terminals (x-term must be installed), one for each
node.

Additionally, a single host can be ran with

    ./a.out ./hosts/A.txt input_data.bin
