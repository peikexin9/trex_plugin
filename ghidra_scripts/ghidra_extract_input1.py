import os
import re
import json
from capstone import *
import sys

# from command import params
class File_Extractor:
    def __init__(self, path):
        self.fields = ['static', 'inst_pos_emb', 'op_pos_emb', 'arch_emb', 'byte1', 'byte2', 'byte3', 'byte4', 'arg_info']
        self.output_dir = sys.path[0].replace("ghidra_scripts","") + "data/inputs"
        self.stack_dir = path
        self.input_dir = path

    def tokenize(self, s):
        s = s.replace(',', ' , ')
        s = s.replace('[', ' [ ')
        s = s.replace(']', ' ] ')
        s = s.replace(':', ' : ')
        s = s.replace('*', ' * ')
        s = s.replace('(', ' ( ')
        s = s.replace(')', ' ) ')
        s = s.replace('{', ' { ')
        s = s.replace('}', ' } ')
        s = s.replace('#', '')
        s = s.replace('$', '')
        s = s.replace('!', ' ! ')

        s = re.sub(r'-(0[xX][0-9a-fA-F]+)', r'- \1', s)
        s = re.sub(r'-([0-9a-fA-F]+)', r'- \1', s)

        return s.split()


    def get_type(self, type_str, agg):

        if '*' in type_str:
            return self.get_type(type_str.replace('*', ''), agg)+'*'
        elif '[' in type_str and ']' in type_str:
            return 'array'
        elif agg['is_enum']:
            return 'enum'
        elif agg['is_struct']:
            return 'struct'
        elif agg['is_union']:
            return 'union'
        elif 'void' in type_str:
            return 'void'

        elif 'float' in type_str:
            return 'float'
        elif 'long' in type_str and 'double' in type_str:
            return 'long double'
        elif 'double' in type_str:
            return 'double'

        elif 'char' in type_str:
            if 'u' in type_str:
                return 'unsigned char'
            return 'signed char'
        elif 'short' in type_str:
            if 'u' in type_str:
                return 'unsigned short'
            return 'signed short'
        elif 'int' in type_str:
            if 'u' in type_str:
                return 'unsigned int'
            return 'signed int'
        elif 'longlong' in type_str:
            if 'u' in type_str:
                return 'unsigned long long'
            return 'signed long long'
        elif 'long' in type_str:
            if 'u' in type_str:
                return 'unsigned long'
            return 'signed long'

        elif 'undefined' in type_str:
            return 'undefined'

        print(type_str)
        return '?you shouldnt be seeing this?'


    def test_hex(self, s):
        try: 
            int(s)
            return True
        except ValueError:
            return False


    def get_reg(self, tokens):
        if tokens[-1] == ']' or self.test_hex(tokens[-1]):
            register = tokens[1].upper()
        else:
            register = tokens[-1].upper()
        return register


    # gets the type of an instruction that has a stack xref
    def get_ds_loc(self, loc_dict, address, funcname):
        for var in loc_dict[funcname]:
            if 'z' in loc_dict[funcname][var].keys():
                if address in loc_dict[funcname][var]['z']:
                    return self.get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])
        return 'no-access'


    # gets the type of an argument using the register name where it's stored
    def get_arg_stack_loc(self, loc_dict, register, funcname):
        for var in loc_dict[funcname]:
            if ('register' in loc_dict[funcname][var] 
                and register == loc_dict[funcname][var]['register']):
                return self.get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])
        return 'undefined'


    # gets overall argument info for each function
    def get_arg_info(self, loc_dict, funcname):
        arg_list = []
        for var in loc_dict[funcname]:
            if var is not ('start-addr' or 'end_addr') and 'register' in loc_dict[funcname][var].keys():
                arg_list.append((loc_dict[funcname][var]['count'], self.get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])))
        arg_list.sort()
        leng = str(len(arg_list))

        while len(arg_list) < 3:
            arg_list.append('##')
        arg_list = [arg_type for (order, arg_type) in arg_list]

        return [leng] + arg_list[:3]


    def hex2str(self, s, b_len=8):
        num = str(s).replace('0x', '')
        # handle 64-bit cases, we choose the lower 4 bytes, thus 8 numbers
        if len(num) > b_len:
            num = num[-b_len:]

        num = '0' * (b_len - len(num)) + num
        return num


    def byte2seq(self, value_list):
        return [value_list[i:i + 2] for i in range(len(value_list) - 2)]


    def extract(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        function_file = {field: open(os.path.join(self.output_dir, f'input0.{field}'), 'w') for field in self.fields}
        function_label = open(os.path.join(self.output_dir, 'input1.label'), 'w')

        with open(os.path.join(self.stack_dir, f'input1_stack.json'), 'r') as f:
            loc_dict = json.loads(f.read())

        with open(os.path.join(self.input_dir, f'input1_code.json'), 'r') as f:
            code_dict = json.loads(f.read())
        
        for func in loc_dict.keys():

            str_list = code_dict[func]['code'].split('\\')
            int_list = [int(i, 16) for i in str_list]
            opcodes = bytes(int_list)
            start_addr = int(code_dict[func]['start_addr'], 16)
            end_addr = int(code_dict[func]['end_addr'], 16)
            func_args = {}

            # input
            static = []
            inst_pos = []
            op_pos = []
            arch = []
            byte1 = []
            byte2 = []
            byte3 = []
            byte4 = []

            # output
            labels = []

            inst_pos_counter = 0

            try:
                for address, size, op_code, op_str in md.disasm_lite(opcodes, start_addr):

                    if start_addr <= address < end_addr:
                        tokens = self.tokenize(f'{op_code} {op_str}')
                        label = self.get_ds_loc(loc_dict, str(hex(address)).replace('0x', ''), func)

                        # get the register and stack location for likely arg vars from the 
                        # op_str and label the instruction by using the register->param type
                        # mapping from Ghidra. A mapping of stack location -> type is stored
                        # for whenever else the location is seen.
                        if label == 'undefined' and '[' in tokens and op_code == 'mov':
                            reg = self.get_reg(tokens)

                            loc = op_str[op_str.find("[")+1:op_str.find("]")]
                            if loc in func_args:
                                label = func_args[loc]

                            else:
                                label = self.get_arg_stack_loc(loc_dict, reg, func)
                                func_args[loc] = label

                        for i, token in enumerate(tokens):
                            if '0x' in token.lower():
                                static.append('hexvar')
                                byte = self.byte2seq(self.hex2str(token.lower()))
                                byte1.append(byte[0])
                                byte2.append(byte[1])
                                byte3.append(byte[2])
                                byte4.append(byte[3])

                            elif token.lower().isdigit():
                                static.append('num')
                                byte = self.byte2seq(self.hex2str(hex(int(token.lower()))))
                                byte1.append(byte[0])
                                byte2.append(byte[1])
                                byte3.append(byte[2])
                                byte4.append(byte[3])
                                
                            else:
                                static.append(token)
                                byte1.append('##')
                                byte2.append('##')
                                byte3.append('##')
                                byte4.append('##')

                            inst_pos.append(str(inst_pos_counter))
                            op_pos.append(str(i))
                            arch.append('x86')

                            labels.append(label)

                        inst_pos_counter += 1

                        # print(str(address) + "\t"+ label+ "\t"+ op_code + "\t"+ op_str )

            except CsError as e:
                print("ERROR: %s" % e)


            arg_info = self.get_arg_info(loc_dict, str(func))

            # skip invalid functions
            #if len(labels) < 30 or len(labels) > 510 or len(set(labels)) == 1:
            function_file[self.fields[0]].write(' '.join(static) + '\n')
            function_file[self.fields[1]].write(' '.join(inst_pos) + '\n')
            function_file[self.fields[2]].write(' '.join(op_pos) + '\n')
            function_file[self.fields[3]].write(' '.join(arch) + '\n')
            function_file[self.fields[4]].write(' '.join(byte1) + '\n')
            function_file[self.fields[5]].write(' '.join(byte2) + '\n')
            function_file[self.fields[6]].write(' '.join(byte3) + '\n')
            function_file[self.fields[7]].write(' '.join(byte4) + '\n')
            function_file[self.fields[8]].write(' '.join(arg_info) + '\n')

            function_label.write(' '.join(labels) + '\n')

        for k in function_file:
            function_file[k].close()
        function_label.close()

file_extr = File_Extractor(sys.path[0].replace("ghidra_scripts","")  +'/data/function')
file_extr.extract()
