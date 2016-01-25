#include <stdio.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	int fd = open(argv[1], O_RDWR);
	if (fd >= 0) {
		int locked = flock(fd, LOCK_EX);
		if (locked == 0) {
			fprintf(stderr, "file [%s] locked for %s secs\n", argv[1], argv[2]);
			sleep(atoi(argv[2]));
			flock(fd, LOCK_UN);
			fprintf(stderr, "unlock file [%s]\n", argv[1]);
		}
	}
	return 0;
}
