server: src/source/server.c src/source/utilities.c 
	gcc -o server src/source/server.c src/source/utilities.c -lpthread -lpcap

client: src/source/client.c src/source/utilities.c 
	gcc -o client src/source/client.c src/source/utilities.c -lpthread -lpcap
