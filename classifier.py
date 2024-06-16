from sklearn.model_selection import StratifiedKFold, learning_curve, train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
import csv, sys, numpy as np, seaborn as sns, matplotlib.pyplot as plt
from sklearn.calibration import LabelEncoder
from imblearn.over_sampling import SMOTE
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from Dataset.dataset import Dataset
from kmeans import kMeans
from preprocessor import *

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

class ModelTrainerClass:
    def __init__(self, filepath, target_column, drop_columns):
        self.filepath = filepath
        self.target_column = target_column
        self.drop_columns = drop_columns
        self.X, self.y = self.load_and_preprocess_data()

    def load_and_preprocess_data(self):
        dataset = Dataset(self.filepath)
        dataset = datasetPreprocessor(dataset)

        # Creazione del primo cluster
        features = dataset.getDataFrame(['Day', 'Month', 'Year', 'Minute', 'Hour', 'Source Port', 'Destination Port', 'Packet Length'])
        kmeans = kMeans().clustering(features, "Info")
        dataset.addDatasetColumn('Temporal Features Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=['Day', 'Month', 'Year', 'Minute', 'Hour', 'Source Port', 'Destination Port', 'Packet Length'])
        dataset.normalizeColumn('Temporal Features Cluster')

        # Creazione del secondo cluster
        features = dataset.getDataFrame(['Attack Type_Intrusion', 'Attack Type_Malware', 'Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'IDS/IPS Alerts', 'Proxy Information', 'Firewall Logs', 'Packet Type_Data', 'Action Taken_Ignored', 'Action Taken_Logged', 'Traffic Type_FTP', 'Traffic Type_HTTP', 'Log Source_Server'])
        kmeans = kMeans().clustering(features, "Attack")
        dataset.addDatasetColumn('Attack Profile Cluster', kmeans.fit_predict(features))
        dataset.dropDatasetColumns(columnsToRemove=['Attack Type_Intrusion', 'Attack Type_Malware', 'Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'IDS/IPS Alerts', 'Proxy Information', 'Firewall Logs', 'Packet Type_Data', 'Action Taken_Ignored', 'Action Taken_Logged', 'Traffic Type_FTP', 'Traffic Type_HTTP', 'Log Source_Server', 'OS_Linux', 'OS_Mac OS', 'OS_Windows', 'OS_iPad OS', 'OS_iPhone OS', 'Browser_Firefox', 'Browser_MSIE', 'Browser_Opera', 'Browser_Safari'])
        dataset.normalizeColumn('Attack Profile Cluster')

        vulnerabilities = dataset.getColumn(self.target_column)
        values = np.array(vulnerabilities)
        oversample = SMOTE()
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(values)
        dataset.dropDatasetColumns(self.drop_columns)
        X = dataset.getDataset()

        return X, y

    def evaluate_model(self, model, X_test, y_test, name):
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

        plt.close('all')
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        class_labels = ['1:TCP', '2: UDP', '3: ICMP']
        plt.yticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xticks(ticks=np.arange(len(class_labels)) + 0.5, labels=class_labels, rotation=0, va='center')
        plt.xlabel('Predicted Class')
        plt.ylabel('True Class')
        plt.title('Confusion Matrix')
        plt.savefig('Evaluation/Confusion_Matrix_' + name + '.png', bbox_inches='tight')

    def cross_validate_model(self, model, X, y):
        cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        print('Cross-validation scores:', cv_scores)
        print('Mean cross-validation score:', np.mean(cv_scores))

    def plot_learning_curve(self, model, X, y, name):
        train_sizes, train_scores, test_scores = learning_curve(model, X, y, cv=5, scoring='accuracy', n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 10))

        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        plt.figure(figsize=(14, 7))

        plt.subplot(1, 2, 1)
        plt.plot(train_sizes, train_scores_mean, 'o-', color='r', label='Training accuracy')
        plt.fill_between(train_sizes, train_scores_mean - train_scores_std, train_scores_mean + train_scores_std, alpha=0.1, color='r')
        plt.plot(train_sizes, test_scores_mean, 'o-', color='g', label='Test accuracy')
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std, test_scores_mean + test_scores_std, alpha=0.1, color='g')
        plt.title('Learning Curve (Accuracy)')
        plt.xlabel('Training examples')
        plt.ylabel('Score')
        plt.legend(loc='best')
        plt.grid()

        plt.subplot(1, 2, 2)
        plt.plot(train_sizes, 1 - train_scores_mean, 'o-', color='r', label='Training loss')
        plt.fill_between(train_sizes, 1 - (train_scores_mean + train_scores_std), 1 - (train_scores_mean - train_scores_std), alpha=0.1, color='r')
        plt.plot(train_sizes, 1 - test_scores_mean, 'o-', color='g', label='Test loss')
        plt.fill_between(train_sizes, 1 - (test_scores_mean + test_scores_std), 1 - (test_scores_mean - test_scores_std), alpha=0.1, color='g')
        plt.title('Learning Curve (Loss)')
        plt.xlabel('Training examples')
        plt.ylabel('Loss')
        plt.legend(loc='best')
        plt.grid()

        plt.savefig('Evaluation/Learning_Curve_' + name + '.png')

    def train_and_evaluate_model(self, model, name):
        X_train, X_test, y_train, y_test = train_test_split(self.X, self.y, test_size=0.2, random_state=42)
        print(f'Training {name}')
        self.cross_validate_model(model, X_train, y_train)
        model.fit(X_train, y_train)
        self.evaluate_model(model, X_test, y_test, name)
        self.plot_learning_curve(model, self.X, self.y, name)
        return model

    def train_model_DecisionTreeClassifier(self, name):
        model = DecisionTreeClassifier(random_state=42)
        return self.train_and_evaluate_model(model, name)

    def train_model_RandomForestClassifier(self, name):
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        return self.train_and_evaluate_model(model, name)

    def train_model_KNN(self, name):
        model = KNeighborsClassifier()
        return self.train_and_evaluate_model(model, name)

    def run(self):
        models = {
            'DecisionTreeClassifier': self.train_model_DecisionTreeClassifier,
            'RandomForestClassifier': self.train_model_RandomForestClassifier,
            'KNN': self.train_model_KNN,
        }

        for model_name, model_function in models.items():
            model_function(model_name)

