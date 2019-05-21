server: src/source/server.c src/source/utilities.c 
	gcc -g3 -o server src/source/server.c src/source/utilities.c -lpthread -lpcap

client: src/source/client.c src/source/utilities.c 
	gcc -g3 -o client src/source/client.c src/source/utilities.c -lpthread -lpcap
clean:
	rm client
	rm server
