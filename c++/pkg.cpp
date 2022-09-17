#include <torch/script.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <cstdlib> 
#include <string>
#include <vector>
#include <map>
using namespace std;
using namespace at;
using namespace c10;

std::string fields[8] = {"arch_emb", "byte1", "byte2", "byte3", "byte4", "inst_pos_emb", "op_pos_emb", "static"};

vector<string> split(const string& str, const string& delim) {  
	vector<string> res;  
	if("" == str) return res;  

	char * strs = new char[str.length() + 1] ;
	strcpy(strs, str.c_str());   
 
	char * d = new char[delim.length() + 1];  
	strcpy(d, delim.c_str());  
 
	char *p = strtok(strs, d);  
	while(p) {  
		string s = p;
		res.push_back(s);  
		p = strtok(NULL, d);  
	}  
 
	return res;  
}


long hex2int(const string& hexStr)
{
    char *offset;
    if(hexStr.length() > 2)
    {
    if(hexStr[0] == '0' && hexStr[1] == 'x')
    {
        return strtol(hexStr.c_str(), &offset, 0);
    }
    }
    return strtol(hexStr.c_str(), &offset, 16);
}


vector<torch::jit::IValue> encode(map<string, string> sentence_dict, map<string, map<string, int>> dictionary) {
    
    c10::Dict<std::string, at::Tensor> token_dict;
    at::Device Devices = c10::kCPU;
    for (int i=0; i<8; i++) {
        std::string line = sentence_dict[fields[i]];
        std::vector<string> words = split(line, " ");
        if (fields[i] != "byte1" and fields[i] != "byte2" and fields[i] != "byte3" and fields[i] != "byte4") {
            vector<int> idsv;
            for (int j=0; j<words.size(); j++) {
                int idx = dictionary[fields[i]][words[j]];
                idsv.push_back(idx);
            }
            at::Tensor ids = torch::tensor(idsv);
            if (ids.dim() == 1) ids = ids.unsqueeze(0);
            token_dict.insert(fields[i], ids.to(Devices));
        }
        else {
            vector<float> idsv;
            for (int j=0; j<words.size(); j++) {
                float idx;
                if (words[j] != "##") idx = hex2int(words[j])/256;
                else idx = 1;
                idsv.push_back(idx);
            }
            at::Tensor ids = torch::tensor(idsv);
            if (ids.dim() == 1) ids = ids.unsqueeze(0);
            token_dict.insert(fields[i], ids.to(Devices));
        }
    }
    std::vector<torch::jit::IValue> inputs;
    inputs.push_back(token_dict);
    return inputs;
}


map< string, map<string, int> > get_dict (string input, string main_folder_path) {
    map< string, map<string, int> > dictionary;
    string line;
    for (int i=0; i<8; i++) {
        stringstream sstream;
        sstream << main_folder_path << "data/dict/" << input << "/" << fields[i] << "/dict.txt";
        string filename = sstream.str();
        std::ifstream inputfile(filename);
        std::map<string, int> tmp;
        int count = 4;
        while (std::getline(inputfile, line)) {
            std::vector<string> parsed = split(line, " ");
            std::string token = parsed[0];
            int num = count;
            tmp[token] = num;
            count++;
        }
        dictionary[fields[i]] = tmp;
    }
    return dictionary;
}


int main(int argc, char** argv) {

    int top = 1;

    string ptc_path = string(argv[0]).erase(string(argv[0]).find("c++"));
    string main_folder_path = string(argv[0]).erase(string(argv[0]).find("ghidra_scripts/c++"));

    torch::jit::script::Module trex;
    try {
        stringstream sstream;
        sstream << ptc_path << "trex.ptc";
        string filename = sstream.str();
        trex = torch::jit::load(filename);
    }
    catch (const c10::Error& e) {
        std::cerr << "error loading the model\n";
        return -1;
    }

    std::vector<at::Scalar> similarities;
    std::map< string, vector<string> > sample0;
    std::map< string, vector<string> > sample1;
    double labels[50];
    double label;

    string line;
    for (int i=0; i<8; i++) {
        stringstream sstream;
        sstream << main_folder_path << "data/inputs/input0." << fields[i];
        string filename = sstream.str();
        fstream inputfile;
        inputfile.open(filename);
        vector<string> tmp;
        while (getline(inputfile, line)) {
            tmp.push_back(line);
        }
        sample0[fields[i]] = tmp;
        inputfile.close();
    }
    for (int i=0; i<8; i++) {
        stringstream sstream;
        sstream << main_folder_path << "data/inputs/input1." << fields[i];
        string filename = sstream.str();
        std::fstream inputfile(filename);
        std::vector<string> tmp;
        while (std::getline(inputfile, line)) {
            tmp.push_back(line);
        }
        sample1[fields[i]] = tmp;
        inputfile.close();
    }

    std::string input0 = "input0";
    std::string input1 = "input1";
    std::map< string, map<string, int> > dictionary0 = get_dict(input0, main_folder_path);
    std::map< string, map<string, int> > dictionary1 = get_dict(input1, main_folder_path);

    for (int i=0; i<top; i++) {
        std::map<string, string> sample0i;
        std::map<string, string> sample1i;
        for (int j=0; j<8; j++) {
            sample0i[fields[j]] = sample0[fields[j]][i];
            sample1i[fields[j]] = sample1[fields[j]][i];
        }

        std::vector<torch::jit::IValue> sample0_tokens = encode(sample0i, dictionary0);
        std::vector<torch::jit::IValue> sample1_tokens = encode(sample1i, dictionary1);

        const unordered_map<basic_string<char>, c10::IValue> kwargs = {{"features_only", true}, {"classification_head_name", "similarity"}};
        at::Tensor emb0 = trex.forward(sample0_tokens, kwargs).toTuple()->elements()[0].toGenericDict().at("features").toTensor();
        at::Tensor emb1 = trex.forward(sample1_tokens, kwargs).toTuple()->elements()[0].toGenericDict().at("features").toTensor();

        at::Scalar pred_cosine = torch::cosine_similarity(emb0, emb1)[0].item();
        cout << pred_cosine << endl;

        stringstream sstream;
        sstream << main_folder_path << "data/result/similarity.csv";
        string filename = sstream.str();
        std::ofstream outputfile;
        outputfile.open(filename);
        cout << filename << endl;
        outputfile << pred_cosine << ',' << 1 << endl;
        outputfile.close();
    }
    return 0;
}