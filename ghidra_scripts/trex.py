import torch
import os
import csv
import re
from itertools import product
import sys

static_field = 'static'
inst_pos_field = 'inst_pos_emb'  # instruction positional embedding
op_pos_field = 'op_pos_emb'  # opcode/operand positional embedding
arch_field = 'arch_emb'
byte_fields = [f'byte{i}' for i in range(1, 5)]

maskable_fields = [static_field] + byte_fields
aux_fields = [inst_pos_field] + [op_pos_field] + [arch_field]
non_byte_fields = [static_field] + [inst_pos_field] + [op_pos_field] + [arch_field]
fields = non_byte_fields + byte_fields

SPACE_NORMALIZER = re.compile(r"\s+")
hexval = [str(i) for i in range(10)] + ['a', 'b', 'c', 'd', 'e', 'f']
real_bytes_idx = set(f'{i}{j}' for i, j in product(hexval, repeat=2))

def encode_line(line, dictionary) -> torch.IntTensor:
    line = SPACE_NORMALIZER.sub(" ", line)
    words = line.strip().split()
    nwords = len(words)
    ids = torch.IntTensor(nwords)

    for i, word in enumerate(words):
        if word in dictionary.keys():
            idx = dictionary[word]
        else: idx=0
        ids[i] = idx
    return ids

def process_token_dict(tokens: dict):
    token_fields = tokens.keys()
    assert len(token_fields) == len(fields)

    for field in fields:
        if tokens[field].dim() == 1:
            tokens[field] = tokens[field].unsqueeze(0)

        if field in non_byte_fields:
            tokens[field] = tokens[field].to(device='cpu').long()
        else:
            tokens[field] = tokens[field].to(device='cpu').float()

    return tokens

def encode(sentence: dict, dictionary: dict) -> torch.LongTensor:
    """
    encode a code piece to its embedding index.
    This is executed individually with extract_features or predict
    """
    sentence_fields = sentence.keys()
    assert len(sentence_fields) == len(fields)

    token_dict = dict()

    for field in non_byte_fields:
        token_dict[field] = encode_line(sentence[field], dictionary[field])

    for field in byte_fields:
        output = torch.ones_like(token_dict[static_field], dtype=torch.float16)
        for i, byte in enumerate(sentence[field].split()):
            if byte not in real_bytes_idx:
                output[i] = float(1)
            else:
                output[i] = int(byte, 16) / 256

        token_dict[field] = output
    return token_dict

loaded = torch.jit.load(sys.path[0] + "/trex.ptc")

samples0 = {field: [] for field in fields}
samples1 = {field: [] for field in fields}
dictionary0 = {field: {} for field in fields}
dictionary1 = {field: {} for field in fields}

for field in fields:
    with open(sys.path[0].replace("ghidra_scripts","") + 'data/inputs/input0.'+field, 'r') as f:
        for line in f:
            samples0[field].append(line.strip())
for field in fields:
    with open(sys.path[0].replace("ghidra_scripts","") + 'data/inputs/input1.'+field, 'r') as f:
        for line in f:
            samples1[field].append(line.strip())
for field in fields:
    with open(sys.path[0].replace("ghidra_scripts","") + 'data/dict/input0/'+field+'/dict.txt', 'r') as f:
        count = 4
        for line in f:
            pairs = line.strip().split(" ")
            dictionary0[field][pairs[0]] = count
            count += 1
for field in fields:
    with open(sys.path[0].replace("ghidra_scripts","") + 'data/dict/input1/'+field+'/dict.txt', 'r') as f:
        count = 4
        for line in f:
            pairs = line.strip().split(" ")
            dictionary1[field][pairs[0]] = count
            count += 1


top = 1
similarities = []

tp_cosine = fp_cosine = fn_cosine = tn_cosine = 0
tp_pair = fp_pair = fn_pair = tn_pair = 0

for sample_idx in range(top):
    sample0 = {field: samples0[field][sample_idx] for field in fields}
    sample1 = {field: samples1[field][sample_idx] for field in fields}

    sample0_tokens = encode(sample0, dictionary0)
    sample1_tokens = encode(sample1, dictionary1)

    sample0_emb = process_token_dict(sample0_tokens)
    print(sample0_tokens)
    sample1_emb = process_token_dict(sample1_tokens)

    # emb0 = trex.predict('similarity', sample0_tokens)
    # emb1 = trex.predict('similarity', sample1_tokens)

    emb0 = loaded(sample0_emb, features_only=True)[0]['features']
    emb1 = loaded(sample1_emb, features_only=True)[0]['features']

    emb0_mean = torch.mean(emb0, dim=1)
    emb1_mean = torch.mean(emb1, dim=1)

    # directly predict pair
    concat_in = torch.cat((emb0_mean, emb1_mean, torch.abs(emb0_mean - emb1_mean), emb0_mean * emb1_mean), dim=-1)
    logits = loaded.classification_heads.similarity_pair(concat_in)

    # cosine similarity of function embedding
    emb0_rep = loaded.classification_heads.similarity(emb0)
    emb1_rep = loaded.classification_heads.similarity(emb1)

    # print(emb0_rep[0, :2], emb1_rep[0, :2])
    pred_cosine = torch.cosine_similarity(emb0_rep, emb1_rep)[0].item()
    pred_pair = logits.argmax(dim=1).item()

    similarities.append([pred_cosine, pred_pair])

with open(sys.path[0].replace("ghidra_scripts","") + 'data/result/similarity.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerows(similarities)
