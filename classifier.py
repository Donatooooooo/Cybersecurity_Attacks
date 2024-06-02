import csv
from os import path
from matplotlib.ticker import FormatStrFormatter, MultipleLocator
import pandas as pd
from sklearn.calibration import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from Dataset.dataset import Dataset
from preprocessor import *
from sklearn.model_selection import StratifiedKFold, learning_curve, train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, multilabel_confusion_matrix
import numpy as np
import matplotlib.pyplot as plt
import sys
import seaborn as sns
from numpy import array
from imblearn.over_sampling import SMOTE
from kmeans import kMeans
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from kmeans import kMeans
import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.optimizers import Adam
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

def load_and_preprocess_data(filepath, target_column, drop_columns):
    dataset = Dataset(filepath)
    dataset = datasetPreprocessor_classifier(dataset)
    dataset.saveDataset("Dataset/Modified_cybersecurity_attacks.csv")
    features = dataset.getDataFrame(['Day', 'Month', 'Year', 'Minute','Hour','Source Port','Destination Port','Packet Length'])
    kmeans = kMeans().clustering(features, "Attack")
    dataset.addDatasetColumn('Own Cluster', kmeans.fit_predict(features))
    dataset.dropDatasetColumns(columnsToRemove=['Day', 'Month', 'Year', 'Minute','Hour','Source Port','Destination Port','Packet Length'])
    dataset.normalizeColumn('Own Cluster')
    dataset.saveDataset("Dataset/Clusterized_dataset.csv")
    vulnerabilities = dataset.getColumn(target_column)
    values = np.array(vulnerabilities)
    oversample = SMOTE()
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(values)
    dataset.dropDatasetColumns(drop_columns)
    X = dataset.getDataset()

    return X, y





def evaluate_model(model, X_test, y_test,name):
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision_micro = precision_score(y_test, y_pred, average='micro')
    recall_micro = recall_score(y_test, y_pred, average='micro')
    f1_micro = f1_score(y_test, y_pred, average='micro')
    f1_macro = f1_score(y_test, y_pred, average='macro')
    print('Accuracy:', accuracy)
    print('Precision (micro):', precision_micro)
    print('Recall (micro):', recall_micro)
    print('F1_micro score:', f1_micro)
    print('F1_macro score:', f1_macro)
    
    with open('Evaluation/metrics_' + name + '.csv', 'w', newline='') as csvfile:
        fieldnames = ['Metric', 'Value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerow({'Metric': 'Accuracy', 'Value': accuracy})
        writer.writerow({'Metric': 'Precision (micro)', 'Value': precision_micro})
        writer.writerow({'Metric': 'Recall (micro)', 'Value': recall_micro})
        writer.writerow({'Metric': 'F1_micro score', 'Value': f1_micro})
        writer.writerow({'Metric': 'F1_macro score', 'Value': f1_macro})


    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    class_labels = ['1:Malware','2: DDoS','3: Intrusion']  
    plt.yticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
    plt.xticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
    plt.xlabel('Predicted Class')
    plt.ylabel('True Class')
    plt.title('Confusion Matrix')
    plt.savefig('Evaluation/Confusion_Matrix_' + name + '.png', bbox_inches='tight')


def cross_validate_model(model, X, y):
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
    print('Cross-validation scores:', cv_scores)
    print('Mean cross-validation score:', np.mean(cv_scores))


def plot_learning_curve(model, X, y, name):
    train_sizes, train_scores, test_scores = learning_curve(model, X, y, cv=5, scoring='accuracy', n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 10))

    train_scores_mean = np.mean(train_scores, axis=1)
    train_scores_std = np.std(train_scores, axis=1)
    test_scores_mean = np.mean(test_scores, axis=1)
    test_scores_std = np.std(test_scores, axis=1)

    plt.figure(figsize=(14, 7))

    plt.subplot(1, 2, 1)
    plt.plot(train_sizes, train_scores_mean, 'o-', color='r', label='Training accuracy')
    plt.fill_between(train_sizes, train_scores_mean - train_scores_std, train_scores_mean + train_scores_std, alpha=0.1, color='r')
    plt.plot(train_sizes, test_scores_mean, 'o-', color='g', label='Cross-validation accuracy')
    plt.fill_between(train_sizes, test_scores_mean - test_scores_std, test_scores_mean + test_scores_std, alpha=0.1, color='g')
    plt.title('Learning Curve (Accuracy)')
    plt.xlabel('Training examples')
    plt.ylabel('Score')
    plt.legend(loc='best')
    plt.grid()

    plt.subplot(1, 2, 2)
    plt.plot(train_sizes, 1 - train_scores_mean, 'o-', color='r', label='Training loss')
    plt.fill_between(train_sizes, 1 - (train_scores_mean + train_scores_std), 1 - (train_scores_mean - train_scores_std), alpha=0.1, color='r')
    plt.plot(train_sizes, 1 - test_scores_mean, 'o-', color='g', label='Cross-validation loss')
    plt.fill_between(train_sizes, 1 - (test_scores_mean + test_scores_std), 1 - (test_scores_mean - test_scores_std), alpha=0.1, color='g')
    plt.title('Learning Curve (Loss)')
    plt.xlabel('Training examples')
    plt.ylabel('Loss')
    plt.legend(loc='best')
    plt.grid()

    plt.savefig('Evaluation/Learning_Curve_' + name + '.png')

def train_model_DecisionTreeClassifier(X, y, name):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print('Decision Tree')
    model = DecisionTreeClassifier(random_state=42)
    cross_validate_model(model, X_train, y_train)
    model.fit(X_train, y_train)
    evaluate_model(model, X_test, y_test, name)
    plot_learning_curve(model, X, y,name)
    return model

def train_model_RandomForestClassifier(X, y, name):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print('Random Forest')
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    cross_validate_model(model, X_train, y_train)
    model.fit(X_train, y_train)
    evaluate_model(model, X_test, y_test, name)
    plot_learning_curve(model, X, y,name)
    return model


def train_model_NaiveBayes(X, y, name):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print('Naive Bayes')
    model = GaussianNB()
    cross_validate_model(model, X_train, y_train)
    model.fit(X_train, y_train)
    evaluate_model(model, X_test, y_test, name)
    plot_learning_curve(model, X, y, name)
    return model

def train_model_KNN(X, y, name):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print('K-Nearest Neighbors')
    model = KNeighborsClassifier()
    cross_validate_model(model, X_train, y_train)
    model.fit(X_train, y_train)
    evaluate_model(model, X_test, y_test, name)
    plot_learning_curve(model, X, y, name)
    return model

def train_model_SVM(X, y, name):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print('Support Vector Machine')
    model = SVC()
    cross_validate_model(model, X_train, y_train)
    model.fit(X_train, y_train)
    evaluate_model(model, X_test, y_test, name)
    plot_learning_curve(model, X, y, name)
    return model

from keras.utils import to_categorical

def evaluete_model_NN(model_name,X_test, y_test, model):
    y_pred = model.predict(X_test)
    y_pred = to_categorical(np.argmax(y_pred, axis=1),3)
    accuracy = accuracy_score(y_test, y_pred)
    precision_micro = precision_score(y_test, y_pred,average='micro')
    recall_micro = recall_score(y_test, y_pred,average='micro')
    f1_micro = f1_score(y_test, y_pred,average='micro')
    f1_macro = f1_score(y_test, y_pred,average='macro')
    print('Accuracy:', accuracy )
    print('Precision:', precision_micro)
    print('Recall:', recall_micro)
    print('F1_micro score:', f1_micro)
    print('F1_macro score:', f1_macro)

    with open('Evaluation/metrics_' + model_name + '.csv', 'w', newline='') as csvfile:
        fieldnames = ['Metric', 'Value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerow({'Metric': 'Accuracy', 'Value': accuracy})
        writer.writerow({'Metric': 'Precision (micro)', 'Value': precision_micro})
        writer.writerow({'Metric': 'Recall (micro)', 'Value': recall_micro})
        writer.writerow({'Metric': 'F1_micro score', 'Value': f1_micro})
        writer.writerow({'Metric': 'F1_macro score', 'Value': f1_macro})

    y_pred_decoded = np.argmax(y_pred, axis=0)
    y_test_decoded = np.argmax(y_test, axis=0)
    cm = confusion_matrix(y_test_decoded, y_pred_decoded)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    class_labels = ['1:Malware','2: DDoS','3: Intrusion']  
    plt.yticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
    plt.xticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
    plt.xlabel('Predicted Class')
    plt.ylabel('True Class')
    plt.title('Confusion Matrix')
    plt.savefig('Evaluation/Confusion_Matrix_' + model_name + '.png', bbox_inches='tight')

def plot_results(model_name,metrics, stopped_epoch, title=None, ylabel=None, ylim=None, metric_name=None, color=None):
    fig, ax = plt.subplots(figsize=(15, 4))
    if not (isinstance(metric_name, list) or isinstance(metric_name, tuple)):
        metrics = [metrics,]
        metric_name = [metric_name,]        
    for idx, metric in enumerate(metrics):    
        ax.plot(metric, color=color[idx])
    
    plt.xlabel("Epoch")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xlim([0, stopped_epoch])
    plt.ylim(ylim)
    ax.xaxis.set_major_locator(MultipleLocator(5))
    ax.xaxis.set_major_formatter(FormatStrFormatter('%d'))
    ax.xaxis.set_minor_locator(MultipleLocator(1))
    plt.grid(True)
    plt.legend(metric_name)   
    plt.savefig('Evaluation/'+ model_name + '.png', bbox_inches='tight')
    plt.close()
    
from keras.callbacks import EarlyStopping, ModelCheckpoint

def train_model_NeuralNetwork(X, y, name):
    SEED_VALUE = 42
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train, X_valid, y_train, y_valid = train_test_split(X_train, y_train, random_state=SEED_VALUE, test_size=0.10)
    y_train = to_categorical(y_train)
    y_test = to_categorical(y_test)
    y_valid = to_categorical(y_valid)
    model = Sequential([
        Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
        Dropout(0.5),
        Dense(64, activation='relu'),
        Dropout(0.5),
        Dense(32, activation='relu'),
        Dense(3, activation='softmax')
    ])

    model.summary()
    #optimizer = RMSprop(learning_rate=0.0001)
    optimizer = Adam(learning_rate=0.0001)
    #optimizer = SGD(learning_rate=0.0001)
    model.compile(optimizer=optimizer,
                    loss="categorical_crossentropy",
                    metrics=["accuracy"])

    if not path.exists('checkpoints/'+ name+'.weights.h5'):
        checkpoint_callback = ModelCheckpoint(filepath='checkpoints/'+ name+'.weights.h5', monitor='val_accuracy', verbose=1, save_weights_only=True, save_best_only=True, mode='max')
        es = EarlyStopping(monitor='val_accuracy', mode='max', verbose=1, patience=15, restore_best_weights=True)

        EPOCHS = 5000
        trained_model=model.fit(X_train, y_train, epochs=EPOCHS, batch_size=64, validation_data=(X_valid, y_valid), callbacks=[es, checkpoint_callback])

        train_loss = trained_model.history["loss"]
        train_acc  = trained_model.history["accuracy"]
        valid_loss = trained_model.history["val_loss"]  
        valid_acc  = trained_model.history["val_accuracy"]
        stopped_epoch = es.stopped_epoch


        plot_results('Val_Loss'+ name,
                    [ train_loss, valid_loss ], 
                    stopped_epoch,       
                    ylabel="Loss", 
                    ylim = [0.0, 1.0],
                    metric_name=["Training Loss", "Validation Loss"],
                    color=['#021bf9', '#a0025c']);
        
        plot_results('Val_accuracy'+ name,
                    [ train_acc, valid_acc ], 
                    stopped_epoch,
                    ylabel="Accuracy",
                    ylim = [0.0, 1.0],
                    metric_name=["Training Accuracy", "Validation Accuracy"],
                    color=['#021bf9', '#a0025c']);
    else:
        model.load_weights('checkpoints/'+name+'.weights.h5')

    evaluete_model_NN(name,X_test, y_test, model)

    return model

def main():
    filepath = "Dataset/datasetNOprepWbasescore.csv"
    target_column = 'Attack Type'
    drop_columns = ['Attack Type']
    name_DT = 'DecisionTree' 
    name_RF = 'Random_Forest'
    name_NB = 'NaiveBayes'
    name_KNN = 'KNN'
    name_SVM = 'SVM'
    X, y = load_and_preprocess_data(filepath, target_column, drop_columns)
    # train_model_RandomForestClassifier(X, y, name_RF)
    # train_model_DecisionTreeClassifier(X, y, name_DT)
    # train_model_NaiveBayes(X, y, name_NB)
    # train_model_KNN(X, y, name_KNN)
    # train_model_SVM(X, y, name_SVM)
    name_NN = 'NeuralNetwork'
    train_model_NeuralNetwork(X, y, name_NN)

if __name__ == "__main__":
    main()
