#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
int login(char *user, char *passwd)
{
   struct spwd *pw;
   char *epasswd;
   pw = getspnam(user);
   if (pw == NULL) {
   return -1;
   }
   printf("Login name: %s\n", pw->sp_namp);
   printf("Passwd : %s\n", pw->sp_pwdp);
   epasswd = crypt(passwd, pw->sp_pwdp);
   if (strcmp(epasswd, pw->sp_pwdp)) {
     return -1;
   }
     return 1;
}

