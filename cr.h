#ifndef _CR_H_
#define _CR_H_

typedef int (*command_callback)(void);

struct command_entry {
  const char* opts;
  const char* command;
  const command_callback callback;
  const command_callback help_callback;
};

#endif /*_CR_H_*/
