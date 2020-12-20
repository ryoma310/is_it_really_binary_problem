#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


void test(){
	flag(0xdeadbeef, 0xdeadbeef);
	return;
}


void winner_record(){
	char buf[128];

	printf("> ");
	read(0, buf, 0x128);

	// TODO: Implement the recording part

	return;
}


void greeting_challenge(){
	char ask_name[] = "can i ask your name?\n> ";
	char msg1[] = "Oh, do you have power of clairvoyance??";
	char msg2[] = "let's record your victory statement!";
	char msg3[] = "NO! it is not the one_time_pad";
	char msg4[] = "enjoy m1z0r3ctf, bye!";
	int one_time_pad;
	int guess;
	char q[] = "can you answer the one time pad??\n> ";
	char name[8];

	srand((unsigned int)time(0));

	one_time_pad = rand();

	printf("%s", ask_name);
	fgets(name, 8, stdin);

	printf("hi!, ");
	printf(name);
	printf("\n");

	printf(q);
	scanf("%d", &guess);
	if (guess == one_time_pad){
		puts(msg1);
		puts(msg2);
		winner_record();
	} else {
		puts(msg3);
	}

	puts(msg4);

	return;
}

void init(){
	alarm(60);
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

int main(void){
	test();
	init();
	puts("welcome to m1z0r3ctf");

	greeting_challenge();

	return 0;
}