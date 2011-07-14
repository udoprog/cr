/*
 * Copyright (c) 2011, John-John Tedro <johnjohn.tedro@toolchain.eu>
 * All rights reserved.
 * see LICENSE
 */
#ifndef _CR_H_
#define _CR_H_

typedef int (*command_callback)(void);

struct command_entry {
  const char* command;
  const command_callback callback;
  const command_callback help_callback;
};

enum outform {
  portable,
  binary
};

#endif /*_CR_H_*/
