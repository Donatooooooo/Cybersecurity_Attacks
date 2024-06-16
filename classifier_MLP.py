from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
import csv, sys, numpy as np, seaborn as sns, matplotlib.pyplot as plt
from matplotlib.ticker import FormatStrFormatter, MultipleLocator
from sklearn.preprocessing import LabelEncoder
from Dataset.dataset import Dataset
from keras.src.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from keras.src.models import Sequential
from keras.src.layers import Dense, Dropout
from keras.src.optimizers import Adam
from keras.src.utils import to_categorical
from kmeans import kMeans
from preprocessor import *
from os import path

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

class ModelTrainer:
    def __init__(self, filepath, target_column, drop_columns):
        self.filepath = filepath
        self.target_column = target_column
        self.drop_columns = drop_columns

    def load_and_preprocess_data(self):
        dataset = Dataset(self.filepath)
        dataset = datasetPreprocessor(dataset)


        features = dataset.getDataFrame(['Day', 'Month', 'Year', 'Minute', 'Hour', 'Source Port', 'Destination Port', 'Packet Length'])
        kmeans = kMeans().clustering(features, "Info")
        dataset.addDatasetColumn('Temporal Features Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=['Day', 'Month', 'Year', 'Minute', 'Hour', 'Source Port', 'Destination Port', 'Packet Length'])
        dataset.normalizeColumn('Temporal Features Cluster')

        vulnerabilities = dataset.getColumn(self.target_column)
        values = np.array(vulnerabilities)
        oversample = SMOTE()
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(values)
        dataset.dropDatasetColumns(self.drop_columns)
        X = dataset.getDataset()

        return X, y

    
    def evaluate_model_MLP(self, model, X_test, y_test, name):
        y_pred = model.predict(X_test)
        y_pred = to_categorical(np.argmax(y_pred, axis=1), 3)
        accuracy = accuracy_score(y_test, y_pred)
        precision_micro = precision_score(y_test, y_pred, average='micro')
        recall_micro = recall_score(y_test, y_pred, average='micro')
        f1_micro = f1_score(y_test, y_pred, average='micro')
        f1_macro = f1_score(y_test, y_pred, average='macro')
        print('Accuracy:', accuracy)
        print('Precision:', precision_micro)
        print('Recall:', recall_micro)
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

        y_pred_decoded = np.argmax(y_pred, axis=0)
        y_test_decoded = np.argmax(y_test, axis=0)
        cm = confusion_matrix(y_test_decoded, y_pred_decoded)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        class_labels = ['1:TCP', '2:UDP', '3:ICMP']
        plt.yticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xlabel('Predicted Class')
        plt.ylabel('True Class')
        plt.title('Confusion Matrix')
        plt.savefig(f'Evaluation/Confusion_Matrix_{name}.png', bbox_inches='tight')

    def plot_results(self, model_name, metrics, stopped_epoch, title=None, ylabel=None, ylim=None, metric_name=None, color=None):
        fig, ax = plt.subplots(figsize=(15, 4))
        if not (isinstance(metric_name, list) or isinstance(metric_name, tuple)):
            metrics = [metrics]
            metric_name = [metric_name]
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
        plt.savefig('Evaluation/' + model_name + '.png', bbox_inches='tight')
        plt.close()

    def train_model_MLP(self, X, y, name):
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
        optimizer = Adam(learning_rate=0.0001)
        model.compile(optimizer=optimizer, loss="categorical_crossentropy", metrics=["accuracy"])

        if not path.exists('Util/checkpoints/' + name + '.weights.h5'):
            checkpoint_callback = ModelCheckpoint(filepath='Util/checkpoints/' + name + '.weights.h5', monitor='val_accuracy', verbose=1, save_weights_only=True, save_best_only=True, mode='max')
            es = EarlyStopping(monitor='val_accuracy', mode='max', verbose=1, patience=15, restore_best_weights=True)

            EPOCHS = 5000
            trained_model = model.fit(X_train, y_train, epochs=EPOCHS, batch_size=64, validation_data=(X_valid, y_valid), callbacks=[es, checkpoint_callback])

            train_loss = trained_model.history["loss"]
            train_acc = trained_model.history["accuracy"]
            valid_loss = trained_model.history["val_loss"]
            valid_acc = trained_model.history["val_accuracy"]
            stopped_epoch = es.stopped_epoch

            self.plot_results('Val_Loss_' + name, [train_loss, valid_loss], stopped_epoch, ylabel="Loss", ylim=[0.0, 1.0], metric_name=["Training Loss", "Validation Loss"], color=['#021bf9', '#a0025c'])
            self.plot_results('Val_accuracy_' + name, [train_acc, valid_acc], stopped_epoch, ylabel="Accuracy", ylim=[0.0, 1.0], metric_name=["Training Accuracy", "Validation Accuracy"], color=['#021bf9', '#a0025c'])
        else:
            model.load_weights('Util/checkpoints/' + name + '.weights.h5')

        self.evaluate_model_MLP(model, X_test, y_test, name)
        return model
