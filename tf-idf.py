import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from Dataset.dataset import Dataset
from preprocessor import basicPreprocessing
from numpy import array
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split 
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

def preprocess(text):
    text = re.sub(r'[^\w\s]', '', text)
    text = text.lower()
    return text

dataset = Dataset("Dataset/cybersecurity_attacks.csv")
dataset = basicPreprocessing(dataset)
corpus = dataset.getColumn('Device Information')
device_info = [preprocess(info) for info in corpus]
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(device_info)

browser = dataset.getColumn('Browser')
values = array(browser)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(values)
oversample = SMOTE()


SEED_VALUE = 42
X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=SEED_VALUE, test_size=0.20, shuffle=True)
X_train, X_valid, y_train, y_valid = train_test_split(X_train, y_train, random_state=SEED_VALUE, test_size=0.10)

X_train, y_train = oversample.fit_resample(X_train, y_train)

model = LogisticRegression()
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")