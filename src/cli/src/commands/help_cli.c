#include <stdio.h>

void help_command(void) {
    printf(
      "Usage:  aura [OPTIONS | COMMAND]\n\n"

      "Commands:\n"
      "\tstart        Start an app entity\n"
      "\tstop         Stop an app entity\n"
      "\trestart      Restart the applicaton\n"
      "\tupdate       Update an app entity\n" /** @todo: could be confusing with version update */
      "\tstatus       Show application status information\n"
      "\tversion      Show version infomation\n"
      "\tget          Get application configuration\n"
      "\tset          Set application configurations\n"
      "\tlist         List application configurations\n" /** @todo: this is a little shady */
      "\tfunction     Manage functions\n"
      "\tdeploy       Deploy function\n"
      "\tremove       Remove function\n"
      "\thealth       Probe application internals\n"
      "\trace         Enable Tracing\n\n"

      "Global Options:\n"
      "\t--config string      Location of config files (default \"/home/lukwiya/.docker\")\n"
      "\t--tlscacert string   Trust certs signed only by this CA (default \"/home/lukwiya/.docker/ca.pem\")\n"
      "\t--tlscert string     Path to TLS certificate file (default \"/home/lukwiya/.docker/cert.pem\")\n"
      "\t--tlskey string      Path to TLS key file (default \"/home/lukwiya/.docker/key.pem\")\n");
}