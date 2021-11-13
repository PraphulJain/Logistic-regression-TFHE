#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int AC = 10;
void addi(){
	AC++;
}
int main(){
	addi();
	printf("%d \n", AC);
}