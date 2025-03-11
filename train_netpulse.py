# -*- coding: utf-8 -*-
"""
Created on Tue Mar 11 22:00:30 2025

@author: gayat
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch
import torch.nn as nn
import torch.optim as optim
import os
import pickle

class LSTMPacketClassifier(nn.Module):
    def __init__(self, input_size=5, hidden_size=64, num_layers=2):
        super(LSTMPacketClassifier, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm1 = nn.LSTM(input_size, hidden_size, num_layers=1, batch_first=True)
        self.lstm2 = nn.LSTM(hidden_size, 32, num_layers=1, batch_first=True)
        self.dropout = nn.Dropout(0.2)
        self.fc1 = nn.Linear(32, 16)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(16, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        h0_1 = torch.zeros(1, x.size(0), self.hidden_size).to(x.device)
        c0_1 = torch.zeros(1, x.size(0), self.hidden_size).to(x.device)
        h0_2 = torch.zeros(1, x.size(0), 32).to(x.device)
        c0_2 = torch.zeros(1, x.size(0), 32).to(x.device)
        out, _ = self.lstm1(x, (h0_1, c0_1))
        out = self.dropout(out)
        out, _ = self.lstm2(out, (h0_2, c0_2))
        out = self.dropout(out[:, -1, :])
        out = self.fc1(out)
        out = self.relu(out)
        out = self.fc2(out)
        out = self.sigmoid(out)
        return out

def load_and_preprocess_data(folder_path="archive (2)"):
    files = [
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv"
    ]
    
    dataframes = []
    for file in files:
        df = pd.read_csv(os.path.join(folder_path, file))
        dataframes.append(df)
    
    data = pd.concat(dataframes, ignore_index=True)
    data = data.dropna()
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    
    features = [
        " Packet Length Mean",
        "Total Length of Fwd Packets",
        " Flow Duration",
        " Destination Port",
        " Total Fwd Packets"
    ]
    print("Selected features:", features)
    print("Available columns:", data.columns.tolist())
    X = data[features].values
    y = data[" Label"].apply(lambda x: 1 if x != "BENIGN" else 0).values
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))
    
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    return X_train, X_test, y_train, y_test, scaler

def train_model(X_train, X_test, y_train, y_test):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = LSTMPacketClassifier(input_size=5, hidden_size=64, num_layers=2).to(device)
    
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    X_train_tensor = torch.tensor(X_train, dtype=torch.float32).to(device)
    y_train_tensor = torch.tensor(y_train, dtype=torch.float32).reshape(-1, 1).to(device)
    X_test_tensor = torch.tensor(X_test, dtype=torch.float32).to(device)
    y_test_tensor = torch.tensor(y_test, dtype=torch.float32).reshape(-1, 1).to(device)
    
    epochs = 10
    batch_size = 32
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for i in range(0, len(X_train), batch_size):
            batch_X = X_train_tensor[i:i+batch_size]
            batch_y = y_train_tensor[i:i+batch_size]
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        model.eval()
        with torch.no_grad():
            outputs = model(X_test_tensor)
            val_loss = criterion(outputs, y_test_tensor)
            accuracy = ((outputs > 0.5).float() == y_test_tensor).float().mean()
        
        avg_loss = total_loss / (len(X_train) // batch_size)
        print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}, Val Loss: {val_loss.item():.4f}, Val Acc: {accuracy:.4f}")
    
    return model

def save_model_and_scaler(model, scaler, model_path="lstm_netpulse_model.pth", scaler_path="scaler.pkl"):
    torch.save(model.state_dict(), model_path)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)

if __name__ == "__main__":
    X_train, X_test, y_train, y_test, scaler = load_and_preprocess_data()
    model = train_model(X_train, X_test, y_train, y_test)
    save_model_and_scaler(model, scaler)
    print("PyTorch model and scaler saved successfully.")