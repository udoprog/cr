#include <stdio.h>

#include <glib.h>

int main(int argc, char* argv[]) {
  gchar* s = g_base64_encode("testar", 6);
  printf("pre: %s", s);
  gsize l;
  gchar* o = g_base64_decode(s, &l);
  printf("res: %s", o);
  g_free(s);
  g_free(o);
  return 0;
}
