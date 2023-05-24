#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>

int main()
{
  //char *cmd = "id\n";
  char *cmd = "ls -la /home/nrv\n";
  //printf("%s", cmd);
  while(*cmd) {
    if (ioctl(0, TIOCSTI, cmd++)) {
      perror("ioctl");
    }
  }
  //execlp("/bin/id", "id", NULL);
}
