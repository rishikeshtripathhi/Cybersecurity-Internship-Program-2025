import random
import re
from collections import Counter
from typing import List, Tuple
import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, random_split
from tqdm import tqdm
import tkinter as tk
from tkinter import scrolledtext, messagebox

# -----------------------
# 1) Dataset generation
# -----------------------
VULN_PATTERNS = [
    "strcpy(%s, %s);",
    "gets(%s);",
    "sprintf(%s, %s);",
    "strcat(%s, %s);",
    "scanf(\"%s\", %s);",
]

SAFE_PATTERNS = [
    "strncpy(%s, %s, %d);",
    "fgets(%s, %d, %s);",
    "snprintf(%s, %d, %s);",
    "memcpy(%s, %s, %d);",
    "scanf(\"%d\", &%s);",
]

VARS = ["buf", "input", "name", "data", "tmp", "s", "dest", "src"]
RANDOM_SNIPPETS = [
    "int main() { char %s[100]; %s return 0; }",
    "void func() { char %s[50]; %s }",
    "char *read() { char *%s = malloc(128); %s return %s; }",
    "void process(char *%s) { %s }",
]

def make_vuln_snippet():
    var1 = random.choice(VARS)
    var2 = random.choice(VARS)
    pattern = random.choice(VULN_PATTERNS)
    num_s = pattern.count("%s")
    num_d = pattern.count("%d")
    args = [random.choice(VARS) for _ in range(num_s)] + [random.choice([16,32,64,100]) for _ in range(num_d)]
    inner = pattern % tuple(args)
    wrapper = random.choice(RANDOM_SNIPPETS)
    count = wrapper.count("%s")
    if count == 2:
        return wrapper % (var1, inner)
    elif count == 3:
        return wrapper % (var1, inner, var2)
    else:
        return wrapper % (var1, inner)

def make_safe_snippet():
    var1 = random.choice(VARS)
    var2 = random.choice(VARS)
    size = random.choice([16,32,64,100])
    pattern = random.choice(SAFE_PATTERNS)
    if pattern.startswith("strncpy"):
        inner = pattern % (var1,var2,size)
    elif pattern.startswith("fgets"):
        inner = pattern % (var1,size,var2)
    elif pattern.startswith("snprintf"):
        inner = pattern % (var1,size,var2)
    elif pattern.startswith("memcpy"):
        inner = pattern % (var1,var2,size)
    elif pattern.startswith("scanf"):
        inner = pattern % (size,var1)
    else:
        inner = pattern % (var1,var2)
    wrapper = random.choice(RANDOM_SNIPPETS)
    count = wrapper.count("%s")
    if count == 2:
        return wrapper % (var1, inner)
    elif count == 3:
        return wrapper % (var1, inner, var2)
    else:
        return wrapper % (var1, inner)

def generate_dataset(n_samples=2000):
    data = []
    for _ in range(n_samples//2):
        data.append((make_vuln_snippet(),1))
        data.append((make_safe_snippet(),0))
    random.shuffle(data)
    return data

# -----------------------
# 2) Tokenizer
# -----------------------
class SimpleTokenizer:
    def __init__(self,min_freq=1):
        self.min_freq = min_freq
        self.vocab = {"<PAD>":0,"<UNK>":1}
        self.inv_vocab = {0:"<PAD>",1:"<UNK>"}
    def fit(self,texts:List[str]):
        counter = Counter()
        for t in texts:
            counter.update(self._tokenize(t))
        idx = len(self.vocab)
        for tok,cnt in counter.items():
            if cnt>=self.min_freq and tok not in self.vocab:
                self.vocab[tok]=idx
                self.inv_vocab[idx]=tok
                idx+=1
    def _tokenize(self,text:str):
        tokens = re.findall(r"[A-Za-z_]\w*|%s|%d|\d+|==|!=|<=|>=|->|[{}()\[\];,\.]|\"[^\"]*\"|'.'|/[*].*?[*]/|//.*?$", text, flags=re.S|re.M)
        if not tokens:
            return list(text)
        return tokens
    def encode(self,text:str,max_len:int):
        tokens = self._tokenize(text)
        ids = [self.vocab.get(tok,self.vocab["<UNK>"]) for tok in tokens]
        if len(ids)>=max_len:
            return ids[:max_len]
        else:
            return ids + [self.vocab["<PAD>"]] * (max_len-len(ids))
    def __len__(self):
        return len(self.vocab)

# -----------------------
# 3) Dataset class
# -----------------------
class CodeDataset(Dataset):
    def __init__(self,samples,tokenizer,max_len=128):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_len = max_len
    def __len__(self):
        return len(self.samples)
    def __getitem__(self,idx):
        code,label = self.samples[idx]
        ids = torch.tensor(self.tokenizer.encode(code,self.max_len),dtype=torch.long)
        return ids,torch.tensor(label,dtype=torch.long)

# -----------------------
# 4) Model
# -----------------------
class TransformerClassifier(nn.Module):
    def __init__(self,vocab_size,embed_dim=128,num_heads=4,num_layers=2,hidden_dim=256,num_classes=2,max_len=128,dropout=0.1):
        super().__init__()
        self.embed = nn.Embedding(vocab_size,embed_dim,padding_idx=0)
        self.pos_embed = nn.Embedding(max_len,embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_dim,nhead=num_heads,dim_feedforward=hidden_dim,dropout=dropout,activation="relu")
        self.transformer = nn.TransformerEncoder(encoder_layer,num_layers=num_layers)
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim,embed_dim//2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim//2,num_classes)
        )
        self.max_len = max_len
    def forward(self,x):
        batch,seq_len = x.shape
        positions = torch.arange(seq_len,device=x.device).unsqueeze(0).expand(batch,-1)
        x = self.embed(x) + self.pos_embed(positions)
        x = x.permute(1,0,2)
        out = self.transformer(x)
        out = out.permute(1,2,0)
        pooled = self.pool(out).squeeze(-1)
        logits = self.classifier(pooled)
        return logits

# -----------------------
# 5) Training
# -----------------------
def train_model(model,train_loader,val_loader,device,epochs=6,lr=1e-3):
    model.to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(),lr=lr)
    best_val = 0.0
    for epoch in range(1,epochs+1):
        model.train()
        pbar = tqdm(train_loader,desc=f"Train E{epoch}")
        for xb,yb in pbar:
            xb,yb = xb.to(device),yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits,yb)
            loss.backward()
            optimizer.step()
            pbar.set_postfix(loss=loss.item())
        val_acc = evaluate(model,val_loader,device)
        print(f"Epoch {epoch}: val_acc={val_acc:.4f}")
        if val_acc>best_val:
            best_val = val_acc
            torch.save(model.state_dict(),"best_model.pt")
    return model

def evaluate(model,loader,device):
    model.eval()
    correct=0
    total=0
    with torch.no_grad():
        for xb,yb in loader:
            xb,yb = xb.to(device),yb.to(device)
            logits = model(xb)
            preds = logits.argmax(dim=-1)
            correct += (preds==yb).sum().item()
            total += xb.size(0)
    return correct/total if total>0 else 0.0

# -----------------------
# 6) Main and GUI
# -----------------------
seed = 42
random.seed(seed)
torch.manual_seed(seed)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Generate dataset and tokenizer
if not os.path.exists("best_model.pt"):
    print("Generating dataset and training model...")
    data = generate_dataset(n_samples=3000)
    texts = [t for t,_ in data]
    tokenizer = SimpleTokenizer(min_freq=1)
    tokenizer.fit(texts)
    dataset = CodeDataset(data,tokenizer,max_len=128)
    n_val = int(0.15*len(dataset))
    n_test = int(0.1*len(dataset))
    n_train = len(dataset)-n_val-n_test
    train_set,val_set,test_set = random_split(dataset,[n_train,n_val,n_test],generator=torch.Generator().manual_seed(seed))
    train_loader = DataLoader(train_set,batch_size=64,shuffle=True)
    val_loader = DataLoader(val_set,batch_size=64,shuffle=False)
    model = TransformerClassifier(vocab_size=len(tokenizer))
    train_model(model,train_loader,val_loader,device,epochs=4,lr=2e-4)
else:
    print("Loading tokenizer and model...")
    data = generate_dataset(n_samples=3000)
    texts = [t for t,_ in data]
    tokenizer = SimpleTokenizer(min_freq=1)
    tokenizer.fit(texts)
    model = TransformerClassifier(vocab_size=len(tokenizer))
    model.load_state_dict(torch.load("best_model.pt",map_location=device))
    model.to(device)
model.eval()

# -----------------------
# GUI
# -----------------------
def predict_snippet():
    code = code_text.get("1.0", tk.END).strip()
    if not code:
        messagebox.showwarning("Input required","Please enter a code snippet!")
        return
    ids = torch.tensor([tokenizer.encode(code,max_len=128)],dtype=torch.long).to(device)
    with torch.no_grad():
        logits = model(ids)
        prob = torch.softmax(logits,dim=-1)[0,1].item()
        label = "VULNERABLE" if prob>0.5 else "SAFE"
        result_label.config(text=f"Prediction: {label} (p_vuln={prob:.2f})")

root = tk.Tk()
root.title("Code Vulnerability Detector")
root.geometry("650x400")

code_text = scrolledtext.ScrolledText(root,wrap=tk.WORD,width=80,height=15)
code_text.pack(pady=10)

predict_btn = tk.Button(root,text="Predict",command=predict_snippet)
predict_btn.pack(pady=5)

result_label = tk.Label(root,text="Prediction: ",font=("Helvetica",14))
result_label.pack(pady=5)

root.mainloop()
