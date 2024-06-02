import pandas as pd
from Dataset.dataset import Dataset
from sklearn.model_selection import train_test_split 
import numpy as np
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.callbacks import EarlyStopping
from sklearn.metrics import mean_squared_error, r2_score
import matplotlib.pyplot as plt
import sys

from kmeans import kMeans
from preprocessor import datasetPreprocessor_regressor

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

def load_and_preprocess_data(filepath, target_column, drop_columns):
    dataset = Dataset(filepath)
    dataset = datasetPreprocessor_regressor(dataset)
    dataset.saveDataset("Dataset/Modified_cybersecurity_attacks.csv")
    features = dataset.getDataFrame(['Day', 'Month', 'Year', 'Minute','Hour','Source Port','Destination Port','Packet Length'])
    kmeans = kMeans().clustering(features, "Attack")
    dataset.addDatasetColumn('Own Cluster', kmeans.fit_predict(features))
    dataset.dropDatasetColumns(columnsToRemove=['Day', 'Month', 'Year', 'Minute','Hour','Source Port','Destination Port','Packet Length'])
    dataset.normalizeColumn('Own Cluster')
    dataset.saveDataset("Dataset/Clusterized_dataset.csv")
    
    y = dataset.getColumn(target_column)
    dataset.dropDatasetColumns(drop_columns)
    X = dataset.getDataset()

    
    
    return X,y

def build_model(input_dim):
    model = Sequential()
    model.add(Dense(100, activation='relu', input_dim=input_dim))
    model.add(Dropout(0.2))
    model.add(Dense(50, activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(1)) 

    model.compile(optimizer='adam', loss='mean_squared_error')
    return model

def train_model(model, X_train, y_train):
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
    history = model.fit(X_train, y_train, epochs=100, batch_size=10, validation_split=0.2, callbacks=[early_stopping])
    return history

def evaluate_model(model, X_test, y_test, history):
    y_pred = model.predict(X_test)

    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    print(f'MSE: {mse}, R^2: {r2}')

    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend()
    plt.show()

def predict_new_example(model, new_example, scaler):
    new_example_scaled = scaler.transform(new_example)
    predicted_score = model.predict(new_example_scaled)
    return predicted_score

def main():
    filepath = "Dataset/datasetNOprepWbasescore.csv"
    target_column = 'Basescore'
    drop_columns = ['Basescore']

    X,y = load_and_preprocess_data(filepath, target_column, drop_columns)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = build_model(X_train.shape[1])
    history = train_model(model, X_train, y_train)
    evaluate_model(model, X_test, y_test, history)
    

if __name__ == "__main__":
    main()