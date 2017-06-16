/* DO NOT TOUCH */
#include <re_types.h>
#include <re_mod.h>

extern const struct mod_export exports_dcmd;
extern const struct mod_export exports_udp;
extern const struct mod_export exports_eth;
extern const struct mod_export exports_stdio;

const struct mod_export *mod_table[] = {
  &exports_dcmd,
  &exports_udp,
  &exports_eth,
  &exports_stdio,
  NULL
};
