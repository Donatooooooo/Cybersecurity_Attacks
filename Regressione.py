import pandas as pd
from Dataset.dataset import Dataset
from sklearn.model_selection import train_test_split 
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.callbacks import EarlyStopping
from sklearn.metrics import mean_squared_error, r2_score
import matplotlib.pyplot as plt
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

dataset = Dataset("Dataset/Altered_cybersecurity_attacks.csv")
y = dataset.getColumn('Anomaly Scores')
dataset.dropDatasetColumns(['Anomaly Scores'])
X = dataset.getDataset()
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)


model = Sequential()
model.add(Dense(100, activation='relu', input_dim=X_train.shape[1]))
model.add(Dropout(0.2))  # Dropout del 20%
model.add(Dense(50, activation='relu'))
model.add(Dropout(0.2))  # Dropout del 20%
model.add(Dense(1))  # Strato di output per la regressione


model.compile(optimizer='adam', loss='mean_squared_error')

# Early stopping per evitare overfitting
early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
history = model.fit(X_train, y_train, epochs=100, batch_size=10, validation_split=0.2, callbacks=[early_stopping])


y_pred = model.predict(X_test)

mse = mean_squared_error(y_test, y_pred)
r2 = r2_score(y_test, y_pred)
print(f'MSE: {mse}, R^2: {r2}')

# Visualizzazione della perdita durante l'addestramento e la validazione
plt.plot(history.history['loss'], label='Training Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')
plt.xlabel('Epochs')
plt.ylabel('Loss')
plt.legend()
plt.show()


new_example = np.array([0.7, 0.5, 0.9, 0.3, 0.6, 0.8, 0.4, 0.2, 0, 0.1, 0, 0.5, 0.6, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0]).reshape(1, -1)

# Normalizzazione del nuovo esempio
scaler = StandardScaler()
new_example_scaled = scaler.fit_transform(new_example)

# Predizione del nuovo esempio
predicted_score = model.predict(new_example_scaled)

print("Valore predetto:", predicted_score[0][0])