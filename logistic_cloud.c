#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

#define M 4 //number of training points
#define CLASSES 2
#define COUNT 9

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}

void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //run the elementary comparator gate n times//
      
  	for (int i=0; i<nb_bits; i++){
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
}

void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const 	TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
    bootsXOR(temp1, a6, b6, bk);  //a xor b  
    bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
    bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
    bootsAND(temp3,a6,b6,bk);             // a and b 
    bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry1,tmp6,bk);


}
void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
	LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

    //run the elementary comparator gate n times//
        
	for (int i=0; i<nb_bits; i++){
        Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
}

void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
    	bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
	        bootsCONSTANT(&temp_result[j],0,bk);
	        bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
        	bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
        	bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}

void is_equal(LweSample* equal, LweSample* a, LweSample* b, const int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
	int i;
	LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	bootsCONSTANT(&equal[0],0,bk);
	bootsCONSTANT(temp2,0,bk);
	for(i=0; i<n_bits; i++){
		bootsXOR(temp1, &a[i], &b[i], bk);
		bootsOR(temp3, temp2, temp1, bk);
		bootsCOPY(temp2, temp3, bk);
		bootsNOT(&equal[0], temp3, bk);
	}
}

void double_bits(LweSample** a, const int n_bits, const int n, const TFheGateBootstrappingCloudKeySet* bk){
	LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(n*n_bits, bk->params);
	int k;
	for(k=0; k<n*n_bits; k++){
		if(k<n_bits){
			bootsCOPY(&temp1[k], &((*a)[k]), bk);
		}
		else{
			bootsCONSTANT(&temp1[k], 0, bk);
		}
	}
	*a = temp1;
}

int BLEN = 16;

struct features{
	LweSample* X1;
	LweSample* X2;
};

struct features X[M];

//For calculating h(x)
void hypothesis(LweSample* result, LweSample** weight, LweSample** X, const int n_features, int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
	int i, k;
	LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(2*n_bits, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(2*n_bits, bk->params);

	for(i=0; i<n_features; i++){
		multiply(temp1, weight[i], X[i], n_bits, bk);
		Adder(temp2, temp1, result, 2*n_bits, bk);
		for(k=0; k<2*n_bits; k++)
			bootsCOPY(&result[k], &temp2[k], bk);
	}
	double_bits(&weight[n_features], n_bits, 2, bk);
	Adder(temp2, weight[n_features], result, 2*n_bits, bk);//Last element of weights is the bias
	for(k=0; k<2*n_bits; k++)
		bootsCOPY(&result[k], &temp2[k], bk);
	//Sigmoid();
}

//For updating weights for one class. Remember we are doing one training point at a time or else we have to take the mean(division)
void update_weight(LweSample** weight, LweSample** X, LweSample* y, const int n_features, int n_bits, const TFheGateBootstrappingCloudKeySet* bk){
	int i, j, k;
	LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(2*n_bits, bk->params);
	LweSample* h = new_gate_bootstrapping_ciphertext_array(2*n_bits, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(4*n_bits, bk->params);
	LweSample* temp4 = new_gate_bootstrapping_ciphertext_array(4*n_bits, bk->params);
	LweSample* temp5 = new_gate_bootstrapping_ciphertext_array(2*n_bits, bk->params);

	for(k=0; k<2*n_bits; k++)
		bootsCONSTANT(&h[k], 0, bk);
	hypothesis(h, weight, X, n_features, n_bits, bk);
	printf("hypothesis done\n");
	double_bits(&y, n_bits, 2, bk);
	subtract(temp1, temp2, h, y, 2*n_bits, bk);
	printf("first substraction done\n");

	for(i=0; i<n_features; i++){
		bootsCONSTANT(&temp2[0], 0, bk);
		bootsCONSTANT(&temp2[1], 0, bk);

		double_bits(&X[i], n_bits, 2, bk);
		printf("bit doubling done\n");
		multiply(temp3, temp1, X[i], 2*n_bits, bk);

		bootsCONSTANT(&temp2[0], 0, bk);
		bootsCONSTANT(&temp2[1], 0, bk);

		double_bits(&weight[i], n_bits, 4, bk);
		subtract(temp4, temp2, weight[i], temp3, 4*n_bits, bk);
		for(k=0; k<4*n_bits; k++)
			bootsCOPY(&weight[i][k], &temp4[k], bk);
		printf("weight update done\n");
	}
	//Update weight[n_features]
	bootsCONSTANT(&temp2[0], 0, bk);
	bootsCONSTANT(&temp2[1], 0, bk);
	subtract(temp5, temp2, weight[n_features], temp1, 2*n_bits, bk);
	for(k=0; k<2*n_bits; k++)
		bootsCOPY(&weight[n_features][k], &temp5[k], bk);
	double_bits(&weight[n_features], 2*n_bits, 2, bk);
	printf("weight update done\n");
}

//For carrying out the whole logistic regression
void logistic_regression(LweSample** weight, LweSample* X[][2], LweSample** y, const int n_features, int n_bits, int n_epochs, const TFheGateBootstrappingCloudKeySet* bk){
	int epoch, tp, i, j, k;
	for(epoch=0; epoch<n_epochs; epoch++){
		printf("epoch %d\n", epoch+1);
		for(tp=0; tp<M; tp++){
			update_weight(weight, X[tp], y[tp], n_features, n_bits, bk);
			for(i=0; i<M; i++){
				if(i != tp){
					for(j=0; j<n_features; j++)
						double_bits(&X[i][j], n_bits, 4, bk);
					double_bits(&y[i], n_bits, 4, bk);
					n_bits = 4 * n_bits;
				}
			}
		}
	}
}


LweSample* cypher[COUNT][2];
LweSample* features[M][2];
LweSample* class[M];

int main(){
	printf("Reading the key...\n");

    //Reading the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //Params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    printf("Reading the precomputations...\n");
    FILE* cloud_precomputations = fopen("cloud_precomputations.data","rb");
    int i, j, k;
    for(i=0; i<COUNT; i++){
    	cypher[i][0] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    	cypher[i][1] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    	for(k=0; k<BLEN; k++)
    		import_gate_bootstrapping_ciphertext_fromFile(cloud_precomputations, &cypher[i][0][k], params);
    	for(k=0; k<BLEN; k++)
    		import_gate_bootstrapping_ciphertext_fromFile(cloud_precomputations, &cypher[i][1][k], params);
    }
    fclose(cloud_precomputations);

    printf("Reading the training data...\n");
    FILE* cloud_train = fopen("cloud_train.data","rb");
    for(i=0; i<M; i++){
    	features[i][0] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    	features[i][1] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    	class[i] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    	for(k=0; k<BLEN; k++)
    		import_gate_bootstrapping_ciphertext_fromFile(cloud_train, &features[i][0][k], params);
    	for(k=0; k<BLEN; k++)
    		import_gate_bootstrapping_ciphertext_fromFile(cloud_train, &features[i][1][k], params);
    	for(k=0; k<BLEN; k++)
    		import_gate_bootstrapping_ciphertext_fromFile(cloud_train, &class[i][k], params);
    }
    fclose(cloud_train);




    LweSample* f_result = new_gate_bootstrapping_ciphertext_array(2*BLEN, params);
    LweSample* w[3];
    w[0] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    w[1] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    w[2] = new_gate_bootstrapping_ciphertext_array(BLEN, params);
    for(k=0; k<BLEN; k++){
    	if(k==0){
    		bootsCONSTANT(&w[0][k], 1, bk);
	    	bootsCONSTANT(&w[1][k], 1, bk);
	    	bootsCONSTANT(&w[2][k], 1, bk);
    	}
    	else{
    		bootsCONSTANT(&w[0][k], 0, bk);
	    	bootsCONSTANT(&w[1][k], 0, bk);
	    	bootsCONSTANT(&w[2][k], 0, bk);
    	}
    }
    for(k=0; k<2*BLEN; k++){
    	bootsCONSTANT(&f_result[k], 0, bk);
    }
    printf("Going into hypothesis\n");
    time_t start_time = clock();
    update_weight(w, features[3], class[3], 2, BLEN, bk);
    //logistic_regression(w, features, class, 2, BLEN, 1, bk);
    time_t end_time = clock();
    printf("Out of hypothesis\n");
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    int int_answer=0;
    int int_answer1=0;
    int int_answer2=0;
    int base = 1;
    for(k=0; k<4*BLEN; k++){
    	int ai = bootsSymDecrypt(&w[0][k], key)>0;
    	int ai1 = bootsSymDecrypt(&w[1][k], key)>0;
    	int ai2 = bootsSymDecrypt(&w[2][k], key)>0;
    	int_answer += base*ai;
    	int_answer1 += base*ai1;
    	int_answer2 += base*ai2;
    	base = base * 2;
    	//int_answer |= (ai<<i);
    }
    printf("Result = %d  %d  %d \n", int_answer, int_answer1, int_answer);
    printf("Executed successfully! Time to execute %ld second\n",(end_time-start_time)/1000000);
}