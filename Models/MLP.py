from sklearn.metrics import mean_squared_error, mean_absolute_error,  mean_squared_log_error
from sklearn.model_selection import train_test_split
from preprocessor import datasetPreprocessor_regressor
import csv, sys, matplotlib.pyplot as plt, numpy as np
from Dataset.dataset import Dataset
from sklearn.preprocessing import StandardScaler
from keras.src.models import Sequential
from keras.src.layers import Dense, Dropout
from keras.src.callbacks import EarlyStopping, ModelCheckpoint
from Models.kmeans import kMeans
from os import path

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

class RegressionModelTrainer:
    def __init__(self, filepath, target_column, drop_columns):
        self.filepath = filepath
        self.target_column = target_column
        self.drop_columns = drop_columns
        self.scaler = StandardScaler()
        
    def load_and_preprocess_data(self):
        dataset = Dataset(self.filepath)
        dataset = datasetPreprocessor_regressor(dataset)
        features = dataset.getDataFrame(['Source Port','Destination Port','Packet Length'])
        kmeans = kMeans().clustering(features, "Network")
        dataset.addDatasetColumn('Network Features Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=['Source Port','Destination Port','Packet Length'])
        dataset.normalizeColumn('Network Features Cluster')
        y = dataset.getColumn(self.target_column)
        dataset.dropDatasetColumns(self.drop_columns)
        X = dataset.getDataset()
        X_scaled = self.scaler.fit_transform(X)

        return train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    def build_model(self, input_dim):
        model = Sequential([
            Dense(100, activation='relu', input_dim=input_dim),
            Dropout(0.2),
            Dense(75, activation='relu'),
            Dropout(0.2),
            Dense(50, activation='relu'),
            Dropout(0.2),
            Dense(1)
        ])
        model.summary()
        model.compile(optimizer='adam', loss='mean_squared_error')
        return model

    def train_model(self, model, X_train, y_train):
        if not path.exists('Util/checkpoints/regression.weights.h5'):
            checkpoint_callback = ModelCheckpoint(filepath='Util/checkpoints/regression.weights.h5', monitor='val_loss', verbose=1, save_weights_only=True, save_best_only=True, mode='min')
            early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
            history = model.fit(X_train, y_train, epochs=100, batch_size=10, validation_split=0.2, callbacks=[early_stopping, checkpoint_callback])
            plt.close('all')
            plt.plot(history.history['loss'], label='Training Loss')
            plt.plot(history.history['val_loss'], label='Validation Loss')
            plt.xlabel('Epochs')
            plt.ylabel('Loss')
            plt.legend()
            plt.savefig('Evaluation/training_history.png')
        else:
            model.load_weights('Util/checkpoints/regression.weights.h5')




    def evaluate_model(self, model, X_test, y_test):
        y_pred = model.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        mae = mean_absolute_error(y_test, y_pred)
        rmse = np.sqrt(mse)
        msle = mean_squared_log_error(y_test, y_pred)

        metrics = {'MSE': mse, 'MAE': mae, 'RMSE': rmse, 'MSLE': msle}

 
        print(f'MSE: {mse}')
        print(f'MAE: {mae}')
        print(f'RMSE: {rmse}')
        print(f'MSLE: {msle}')

        with open('Evaluation/metrics_regression_MLP.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Metric', 'Value'])
            for key, value in metrics.items():
                writer.writerow([key, value])

        return mse, mae, rmse, msle, y_pred




