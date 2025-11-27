#include "util/echo_off.h"

#if _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace file_encrypt::util {
#if _WIN32
static DWORD oldmode = 0;
#else
static termios old_tty = {};
#endif

EchoOff::EchoOff() {
#if _WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

  DWORD mode = 0;
  GetConsoleMode(hStdin, &mode);
  old_mode = mode;
  mode &= ~ENABLE_ECHO_INPUT;
  SetConsoleMode(hStdin, mode);
#else
  termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  old_tty = tty;
  tty.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

EchoOff::~EchoOff() {
#if _WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

  SetConsoleMode(hStdin, oldmode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &old_tty);
#endif
}

}  // namespace file_encrypt::util