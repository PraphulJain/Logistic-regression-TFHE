#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#define COUNT 9
#define BLEN 64
#define M 4

LweSample* cypher[COUNT][2];
LweSample* training_data[M][3];

int main(){
	//generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    printf("Starting process...\n");

    //Encrypting sigmoid precomputations
    FILE* fp = fopen("sigmoid.txt", "r");
    printf("File opened\n");
    int i, j, k;
    for(i=0; i<COUNT; i++){
		int a, b;
		fscanf(fp, "%d", &a);
		fscanf(fp, "%d", &b);
		cypher[i][0] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
		cypher[i][1] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
		for(k=0; k<BLEN; k++){
			bootsSymEncrypt(&cypher[i][0][k],(a>>k)&1,key);
			bootsSymEncrypt(&cypher[i][1][k],(b>>k)&1,key);
    	}
    }
    fclose(fp);
    printf("File closed\n");

    //Encrypting training data
    FILE* fp1 = fopen("training.txt", "r");
    printf("File opened\n");
    for(i=0; i<M; i++){
		int x1, x2, y;
		fscanf(fp1, "%d", &x1);
		fscanf(fp1, "%d", &x2);
		fscanf(fp1, "%d", &y);
		training_data[i][0] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
		training_data[i][1] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
		training_data[i][2] = new_gate_bootstrapping_ciphertext_array(BLEN,params);
		for(k=0; k<BLEN; k++){
			bootsSymEncrypt(&training_data[i][0][k],(x1>>k)&1,key);
			bootsSymEncrypt(&training_data[i][1][k],(x2>>k)&1,key);
			bootsSymEncrypt(&training_data[i][2][k],(y>>k)&1,key);
    	}
    }
    fclose(fp1);
    printf("File closed\n");

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //export precomputations to cloud
	FILE* cloud_data=fopen("cloud_precomputations.data","wb");
	for(i=0; i<COUNT; i++)
    	for(j=0; j<2; j++)
    		for(k=0; k<BLEN; k++)
    			export_gate_bootstrapping_ciphertext_toFile(cloud_data, &cypher[i][j][k],params);
    fclose(cloud_data);

    //export training data to cloud
	FILE* cloud_data1=fopen("cloud_train.data","wb");
	for(i=0; i<M; i++)
    	for(j=0; j<3; j++)
    		for(k=0; k<BLEN; k++)
    			export_gate_bootstrapping_ciphertext_toFile(cloud_data1, &training_data[i][j][k],params);
    fclose(cloud_data1);

    //clean up all pointer
    for(i=0; i<COUNT; i++)
    	for(j=0; j<2; j++)
    		delete_gate_bootstrapping_ciphertext_array(BLEN,cypher[i][j]);
    for(i=0; i<M; i++)
    	for(j=0; j<3; j++)
    		delete_gate_bootstrapping_ciphertext_array(BLEN,training_data[i][j]);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}