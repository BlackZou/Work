#include <numeric>
#include "FHE.h"
#include <iostream>
#include "EncryptedArray.h"
#include <fstream>
#include <sstream>
#include <string>
//using namesapce std;
NTL_CLIENT

//定义参数
//long m = 8192; 
long m = 2048;                   // Specific modulus
//long p = 65537;                 // Plaintext base [default=2], should be a prime number
long p = 270337;
long r = 1; 
long c = 6; 
long L = 1200;                  // Number of levels in the modulus chain [default=heuristic]



//读取MNIST手写数字，数据
vector<vector<long int>> r_csv(string fname,int n_line){
	ifstream fin(fname);
	string line;
	vector<vector<long int>> field1;
	int c_n=0;
	while(getline(fin,line)){
		istringstream sin(line);
		vector<long int> fields;
		string field;
		while(getline(sin,field,',')){
			fields.push_back(stoi(field,0,10));
		}
		c_n+=1;
		field1.push_back(fields);
		if (c_n==n_line){return field1;}
	}
}
//读取权重、偏置
vector<vector<long int>> r_w_csv(vector<vector<int>> &Nega){
	//ifstream fin("./w_b.csv");
	ifstream fin("./code/w_b2.csv");
	string line;
	vector<vector<long int>> field1;
	int num_v;
	while(getline(fin,line)){
		istringstream sin(line);
		vector<int> Nega_tmp;
		vector<long int> fields;
		string field;
		int n=0;
		int num_Pos=0;
		while(getline(sin,field,',')){
			num_v=int(atof(field.c_str())*100);
			if(num_v<0){Nega_tmp.push_back(num_Pos);}
			num_Pos+=1;
			fields.push_back(num_v);
		}
		n+=1;
		Nega.push_back(Nega_tmp);
		field1.push_back(fields);
		if (n==11){return field1;}
	}
}
//存储负权重的位置
long int Ne(vector<vector<int>> Nega,vector<long int> pp1,long p,int i){
	for (int j=0;j<Nega[i].size();j++){
		//if(flag==0){std::cout << Nega[i][j] << " " << p1[Nega[i][j]] << " " <<endl;}
		if(pp1[Nega[i][j]]!=0){pp1[Nega[i][j]]-=p;}
	}
	long int sum=accumulate(pp1.begin(),pp1.end(),0);
	//std::cout << sum << std::endl;
	//std::cout << pp1 << std::endl;
	return sum;
}

//运算出标签，输入：权重向量c2、偏置ww[10]、MNIST数据c1、负权重Nega
int Calc_lable(Ctxt c1,vector<Ctxt> c2,vector<long int>bb,vector<vector<int>> Nega,vector<int> label_l,\
const EncryptedArray& ea,FHESecKey sk,const FHEPubKey& pk){
	Ctxt cc1(pk);
	std::vector<long int> pp1;
	std::vector<long int> result_p;
	long int sum_p;
	for(int i=0;i<c2.size();i++){
		//ea.encrypt(cc1,pk,p1);
		cc1=c1;
		cc1*=c2[i];
		ea.decrypt(cc1,sk,pp1);
		sum_p=Ne(Nega,pp1,p,i);
		//if(i==0){cout << pp1 << endl;}
		result_p.push_back(sum_p);
	}
	//std::cout << result_p << std::endl;
	for(int i=0;i<result_p.size();i++){
		result_p[i]+=bb[i]*255;
	}
	cout << result_p << endl;
	
	//计算出索引，手写数字
	long int max=result_p[0];
	int max_index=0;
	for(int i=1;i<result_p.size();i++){
		if (max<result_p[i]){max=result_p[i];max_index=i;}
	}
	//cout << max_index << "：" << max << "：" << label_l[0] << endl;
	return max_index;
}

int main(int argc, char *argv[]) {

	//产生FHEtext对象
	cout << "Initializing context..." << flush;
	FHEcontext context(m,p,r);  //initialize context
	buildModChain(context, L, c);  //modify the context
	cout << "OK!" << endl;

	// Print the context
	context.zMStar.printout();
	std::cout << std::endl;
	//产生公钥、私
	cout << "Generating keys..." << flush;
	FHESecKey sk(context);  //construct a secret key structure
	sk.GenSecKey();  //actually generate a secret key with Hamming weight w
	addSome1DMatrices(sk);
	const FHEPubKey& pk= sk;  //An "upcast": FHESecKey is a subclass of FHEPubKey
	cout << "OK!" << endl;

	//定义明文内容，读取MNIST手写数据
	vector<vector<long int>> p1_l;
	std::vector<long int> p1;
	vector<int> label_l;
	string fname="./code/mnist_test.csv";
	//string fname="./code/111.csv";
	p1_l=r_csv(fname,2);
	for (int i=0;i<p1_l.size();i++){
		label_l.push_back(p1_l[i][0]);
		p1_l[i].erase(p1_l[i].begin());
	}
	std::cout << "p1 size:" << p1_l.size() << std::endl;
	//p1=p1_l[0];
	//p1.erase(p1.begin());

	//读取权重的负值位置
	vector<vector<int>> Nega;
	std::vector<vector<long int>> ww;
	ww=r_w_csv(Nega);
	//for (int i=0;i<10;i++) {ww[i]=r_c[i];}
	//std::cout << ww[10] << std::endl; //ww[10]是偏置

	//将Array-->FHE加密对象ea
	const EncryptedArray& ea = *(context.ea);
  	// Get the number of slot (phi(m))
  	long nslots = ea.size();
  	std::cout << "Number of slots: " << nslots << std::endl;
	
	//用ea进行转换、加密（MNIST数据、权重）
	Ctxt ctmp(pk);
	vector<Ctxt> c2;
	for (int i = 0; i < 10; i++) {
		for (int j=ww[i].size();j<ea.size();j++){
			ww[i].push_back(0);
		}
		ea.encrypt(ctmp,pk,ww[i]);
		c2.push_back(ctmp);
	}

	//运算
	int max_index;
	for (int k=0;k<p1_l.size();k++){
		p1=p1_l[k];
		Ctxt c1(pk);
		for (int i = p1.size(); i < ea.size(); i++) {
			p1.push_back(0);
		}
		ea.encrypt(c1,pk,p1);
		max_index = Calc_lable(c1,c2,ww[10],Nega,label_l,ea,sk,pk);
		cout << max_index <<  "：" << label_l[k] << endl;
	}
	return 0;
}
